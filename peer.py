"""
The peer class is really a lot bigger than I was expecting.
"""

import socket
import ssl
import os
import cPickle # Supposed to be orders of magnitude faster than `pickle`, but with some limitations limitations on (esoteric) subclassing of `Pickler`/`Unpickler`.
import hashlib
import random
import shutil
import struct
import inspect
import json
import copy
from urllib2 import urlopen
from collections import namedtuple
import threading
import time
import Crypto.Signature.PKCS1_v1_5, Crypto.Hash, Crypto.Cipher.AES, Crypto.PublicKey.RSA, Crypto.Random
import base64
import directory_merkel_tree
import subprocess
import argparse

# Named tuples have (immutable) class-like semantics for accessing fields, but are straightforward to pickle/unpickle.
# The following types are for important data whose contents and format should be relatively stable at this point.
PeerData = namedtuple('PeerData', 'ip_address, store_revisions')
StoreData = namedtuple('StoreData', 'revision_data, peers')
RevisionData = namedtuple('RevisionData', 'revision_number, store_hash, signature')
Metadata = namedtuple('Metadata', 'peer_id, peer_dict, store_id, store_dict, aes_key, aes_iv, merkel_tree')


# A needed constant for unpacking messages
HEADER_SIZE = struct.calcsize('!I')

INVALID_REVISION = None #RevisionData(revision_number=0, store_hash=None, signature=None)

class ManualDisconnectException(Exception):
  pass

class Peer:
  
  #########################
  # Primary functionality #
  #########################
  
  # These are the goods, implemented at a higher level than the lower methods.

  def __init__(self,
               own_store_directory=os.path.join(os.getcwd(), 'own_store'),
               root_directory=os.getcwd(),
               debug_verbosity=0,
               debug_preamble=None,
               _metadata=None,
               lock=threading.RLock()
               ):
    """Initialize a `Peer` object."""
    
    # Set any incoming overrides
    self.own_store_directory = own_store_directory
    self.root_directory = root_directory
    self.debug_verbosity = debug_verbosity
    self.debug_preamble = debug_preamble
    self._metadata = _metadata
    self.lock = lock
    
    self.initialize_directory_structure()
        
    self.initialize_keys()
    
    self.load_metadata_file()
    

  def run(self, client_sleep_time=5):
    """Start operating as a both a peer client and peer server."""
    # Do preliminary updates before coming online
    self.update_ip_address()
    self.check_store()
        
    peer_client_thread = threading.Thread(target=self.run_peer_server, args=())
    peer_client_thread.start()
    self.run_peer_client()


  def run_peer_client(self, sleep_time=5, timeout=2):
    self.debug_print( (1, 'Peer client mode running.'))
    
    while True:      
      # Find a peer to connect to and initiate a session.
      server_peer_id = self.select_sync_peer()
      
      if server_peer_id:
        try:        
          self.debug_print( [(1, 'Attempting to connect to peer server.'),
                             (2, 'server_peer_id = {}'.format([server_peer_id])),
                             (2, 'ip_address = {}'.format(self.peer_dict[server_peer_id].ip_address))] )
#           self.lock.acquire()
          skt_ssl = self.connect_to_peer(server_peer_id, timeout)
          try:
            self.debug_print( (1, 'Successfully connected to peer server. Initiating peer client session.') )
            self.peer_client_session(skt_ssl)
          except socket.error:
            self.debug_print( (1, 'Disconnected from peer server due to socket error.') )
          except ManualDisconnectException:
            self.debug_print( (2, 'The peer client session did not complete in a successful sync.') )
          finally:
#             self.lock.release()
            try:
              skt_ssl.shutdown(socket.SHUT_RDWR)
              skt_ssl.close()
            except socket.error:
              self.debug_print( (3, 'Socket already closed by peer server.') )
            
          self.debug_print( (1, 'Disconnected from peer server.') )
        except (socket.timeout, socket.error):
          self.debug_print( (2, 'Could not connect to peer server.') )
      
      # Sleep a while before iterating the loop again.
      self.debug_print( (1, 'Peer client mode going to sleep.') )
      time.sleep(sleep_time)
      self.debug_print( (1, 'Peer client mode waking up.') )
      self.check_store() # FIXME: This is an intensive operation. Instead watch the filesystem for changes and mark with a "dirty" flag.
      self.update_ip_address()

    
     
  def run_peer_server(self):
    self.debug_print( (1, 'Peer server mode running.'))
    skt_listener = self.create_listening_socket(timeout=5)
    
    while True:
      self.debug_print( (1, 'Waiting for a peer client to connect.') )
      # TODO: Will want to deal with multiple peer clients eventually.
      try:
        skt_raw, (peer_ip, _) = skt_listener.accept()
        self.debug_print( (1, 'Connected to a peer client from \'{}\'. Initiating peer server session.'.format(peer_ip)))      
        skt_ssl = ssl.wrap_socket(skt_raw, server_side=True, keyfile=self.private_key_file, certfile=self.x509_cert_file, ssl_version=ssl.PROTOCOL_SSLv3)
#         self.lock.acquire()
        try:
          self.peer_server_session(skt_ssl, peer_ip)
        except socket.error:
          self.debug_print( (1, 'Disconnected from peer client due to socket error.') )
        except ManualDisconnectException:
          self.debug_print( (2, 'The peer server session did not complete in a successful sync.') )
        finally:
#           self.lock.release()
          try:
            skt_ssl.shutdown(socket.SHUT_RDWR)
            skt_ssl.close()
          except socket.error:
            self.debug_print( (3, 'Socket already closed by peer client.') )
          
        self.debug_print( (1, 'Disconnected from peer client.') )
      except (socket.timeout, socket.error):
        pass
      

  def peer_server_session(self, skt_ssl, peer_ip):
    self.debug_print( (2, 'Waiting for peer client\'s handshake message.'))    
    pickled_payload = self.receive_expected_message(skt_ssl, 'handshake_msg')
    (client_peer_id, client_peer_dict) = self.unpickle('handshake_msg', pickled_payload)
    self.debug_print( [(1, 'Handshake message received from peer client.'),
                       (2, 'client_peer_id = {}'.format([client_peer_id])),
                       (3, 'client_peer_dict = {}'.format([client_peer_dict]))] )
    
    self.debug_print( (1, 'Attempting to learn from peer client\'s reports about itself.'))
    self.record_peer_data(client_peer_id, client_peer_dict[client_peer_id])
    
    # If the peer client is of interest, handshake back.
    if client_peer_id in self.peer_dict.keys():
      self.debug_print( (1, 'Sending handshake message to peer client.'))
      self.send_handshake_msg(skt_ssl)
    # Otherwise, disconnect.
    else:
      self.debug_print( (1, 'No stores in common with peer client. Disconnecting.'))
      self.send_disconnect_req(skt_ssl, 'No stores in common.')
      raise ManualDisconnectException()

    self.debug_print( (1, 'Store match!') )

    # FIXME: For known client peers, will want to verify the public key provided to the SSL.

    # TODO: Should only ask for peer's public key when it's unknown (?)
    # Receive and record the peer client's public key file.
    self.debug_print( (2, 'Waiting for peer client\'s public key.'))
    pickled_payload = self.receive_expected_message(skt_ssl, 'public_key_msg')
    public_key_file_contents = self.unpickle('public_key_msg', pickled_payload)
    
    # If the peer client is of interest to us and we don't have their public key, record it.
    if (client_peer_id in self.peer_dict.keys()) \
        and (not os.path.isfile(self.get_peer_key_path(client_peer_id))):
      self.debug_print( [(1, 'Recording public key for new peer.'),
                         (4, 'public_key_file_contents = {}'.format([public_key_file_contents]))] )
      with open(self.get_peer_key_path(client_peer_id), 'w') as f:
        f.write(public_key_file_contents)
        
    # Otherwise, check the supplied key against what we have on record.
    # FIXME: We should really be getting this from the SSL socket.
    elif (client_peer_id in self.peer_dict.keys()) \
        and (self.get_peer_key(client_peer_id) != Crypto.PublicKey.RSA.importKey(public_key_file_contents)):
      self.debug_print( (1, 'Public key supplied by peer client does not match what we have on record. Disconnecting.') )
      self.send_disconnect_req(skt_ssl, 'Public key failed verification.')
      raise ManualDisconnectException()

    self.debug_print( (1, 'Parsing useful gossip from peer client.'))
    self.learn_peer_gossip(client_peer_dict)
    
    # Get the peer client's sync request.
    self.debug_print( (2, 'Waiting for peer client\'s sync request.') )
    pickled_payload = self.receive_expected_message(skt_ssl, 'sync_req')
    sync_store_id = self.unpickle('sync_req', pickled_payload)
    self.debug_print( [(1, 'Peer client sync request received.'),
                       (2, 'sync_store_id = {}'.format([sync_store_id]))] )
    
    # Figure out what type of sync we'll be conducting.
    sync_type = self.determine_sync_type(client_peer_id, sync_store_id)
    
    # Sync
    self.debug_print( (1, 'Executing sync of type \'{}\' with peer client.'.format(sync_type)) )
    self.do_sync(skt_ssl, sync_type, client_peer_id, sync_store_id)
    self.debug_print( (1, 'Successfully completed sync with peer client.'))
    

    # Session over, send the peer client a disconnect request.
    self.debug_print( (1, 'Peer server session complete. Disconnecting.'))
    self.send_disconnect_req(skt_ssl, 'Session complete.')
  
      
  def peer_client_session(self, skt_ssl):
    # Initiate handshake with the peer server, providing pertinent metadata about ourselves and gossip.
    self.debug_print( (1, 'Sending handshake message to peer server.'))
    self.send_handshake_msg(skt_ssl)
    
    self.debug_print( (2, 'Waiting for peer server\'s handshake message.'))
    pickled_payload = self.receive_expected_message(skt_ssl, 'handshake_msg')
    (server_peer_id, server_peer_dict) = self.unpickle('handshake_msg', pickled_payload)
    self.debug_print( [(1, 'Handshake message received from peer server.'),
                       (2, 'server_peer_id = {}'.format([server_peer_id])),
                       (3, 'server_peer_dict = {}'.format([server_peer_dict]))] )

    # The peer server's knowledge of itself is at least as up to date as ours, so trust what it says.
    self.record_peer_data(server_peer_id, server_peer_dict[server_peer_id])
    
    self.debug_print( (1, 'Parsing useful gossip from peer server.'))
    self.learn_peer_gossip(server_peer_dict)

    # FIXME
    # Always send public key file to server
    self.debug_print( (1, 'Sending public key to peer server'))
    self.send_public_key_msg(skt_ssl)
    
    # Select a store to sync with the peer server.
    sync_store_id = self.select_sync_store(server_peer_id)
    
    # Quit the session if we couldn't find a store to sync.
    if not sync_store_id:
      self.debug_print( (1, 'No valid mutual stores to sync or check. Disconnecting.') )
      self.send_disconnect_req(skt_ssl, 'No valid mutual stores to sync or check.')
      raise ManualDisconnectException()
    
    # Initiate a sync.
    self.debug_print( [(1, 'Requesting sync with peer server.'),
                       (2, 'sync_store_id = {}'.format([sync_store_id]))] )
    self.send_sync_req(skt_ssl, sync_store_id)
    
    # Figure out what type of sync we'll be conducting.
    sync_type = self.determine_sync_type(server_peer_id, sync_store_id)
    
    # Sync
    self.debug_print( (1, 'Executing sync of type \'{}\' with peer server.'.format(sync_type)))
    self.do_sync(skt_ssl, sync_type, server_peer_id, sync_store_id)
    self.debug_print( (1, 'Successfully completed sync with peer server.') )

    
    self.debug_print( (1, 'Session complete.') )
    
    self.debug_print( (2, 'Waiting for peer server\'s disconnect request.'))
    pickled_payload = self.receive_expected_message(skt_ssl, 'disconnect_req')
    disconnect_message = self.unpickle('disconnect_req', pickled_payload)
    self.debug_print( [(1, 'Peer requested disconnect reporting the following:'),
                       (1, disconnect_message)] )
    
  
  def do_sync(self, skt, sync_type, peer_id, store_id):
    if sync_type == 'receive':
      self.sync_receive(skt, peer_id, store_id)
    elif sync_type == 'send':
      self.sync_send(skt, peer_id, store_id)
    elif sync_type == 'check':
      self.sync_check(skt, peer_id, store_id)
    else:
      # TODO: Raise a meaningful exception.
      raise Exception()
      
  ####################
  # Class attributes #
  ####################
  
  # FIXME: Beware the unsafety if accessing mutable fields from multiple threads.
  listening_port = 51338 # TODO: Magic number. Ideally would want listening listening_port number to be configurable per peer.
  
  
  ##########################
  # Initialization methods #
  ##########################
  
  def generate_initial_metadata(self):
    """
    Generate a peer's important metadata the first time it is instantiated.
    """
    # FIXME: Just do full initialization here (i.e. including revision and tree data).
    
    peer_id = self.generate_peer_id()
    store_id = self.generate_store_id()    
    ip_address = None # Automatically set upon running the peer
    own_revision_data = INVALID_REVISION # Automatically updated upon running the peer.
    merkel_tree = None # Running the peer will cause a check of the store which will populate this and sign a new revision
    initial_peers = set([peer_id])
    aes_key = Crypto.Random.new().read(Crypto.Cipher.AES.block_size)
    aes_iv = Crypto.Random.new().read(Crypto.Cipher.AES.block_size)
    
    # FIXME: Idempotently initialize/ensure personal directory structure here including initial revision number.
    peer_dict = {peer_id: PeerData(ip_address, {store_id: own_revision_data})}
    store_dict = {store_id: StoreData(own_revision_data, initial_peers)}
    
    # Load the initial values into a `Metadata` object.
    metadata = Metadata(peer_id, peer_dict, store_id, store_dict, aes_key, aes_iv, merkel_tree)
    return metadata
    
  
  def generate_peer_id(self):
    """
    Generate a quasi-unique ID for this peer using a hash (SHA-256, which
    currently has no known collisions) of the owner's public key "salted" with 
    32 random bits.
    """
    cipher = hashlib.sha256(self.public_key.exportKey())
    cipher.update(Crypto.Random.new().read(4))
    peer_id = cipher.digest()
    self.debug_print( (2, 'Generated new peer ID: {}'.format([peer_id])) )
    return peer_id
    

  def generate_store_id(self, public_key=None):
    """
    Store IDs are meant to uniquely identify a store/user. They are essentially
    the RSA public key, but we use use their SHA-256 hash to "flatten" them to
    a shorter, predictable length.
    """
    # Default to using own public key.
    if not public_key:
      public_key = self.public_key
      
    store_id = hashlib.sha256(public_key.exportKey()).digest()
    self.debug_print( (2, 'Generated new store ID: {}'.format([store_id])) )
    return store_id

  #######################
  # Config file methods #
  #######################
  
  def initialize_directory_structure(self):
    """
    Produce the directory structure to store keys, stores, and config files.
    """
    if not os.path.exists(self.own_store_directory):
      os.makedirs(self.own_store_directory)
    
    self.config_directory = os.path.join(self.root_directory, '.config')
    
    self.key_directory = os.path.join(self.config_directory, 'keys')
    
    self.own_keys_directory = os.path.join(self.key_directory, 'own_keys')
    if not os.path.exists(self.own_keys_directory):
      os.makedirs(self.own_keys_directory)
    
    self.peer_keys_directory = os.path.join(self.key_directory, 'peer_keys')
    if not os.path.exists(self.peer_keys_directory):
      os.makedirs(self.peer_keys_directory)
      
    self.store_keys_directory = os.path.join(self.key_directory, 'store_keys')
    if not os.path.exists(self.store_keys_directory):
      os.makedirs(self.store_keys_directory)
    
    self.stores_directory = os.path.join(self.root_directory, 'stores')
    if not os.path.exists(self.stores_directory):
      os.makedirs(self.stores_directory)
    
    
  def initialize_keys(self):
    """
    Produce public and private keys if they don't exist. Then, load the public
    and private keys.
    """
    self.private_key_file = os.path.join(self.own_keys_directory, 'private_key.pem')
    if os.path.isfile(self.private_key_file):
      with open(self.private_key_file, 'r') as f:
        self.private_key = Crypto.PublicKey.RSA.importKey(f.read())
    else:
      self.private_key = Crypto.PublicKey.RSA.generate(2048)
      with open(self.private_key_file, 'w') as f:
        f.write(self.private_key.exportKey())
    
    # Not sure we actually need to use the public key file...
    self.public_key_file = os.path.join(self.own_keys_directory, 'public_key.pem')
    if os.path.isfile(self.public_key_file):
      with open(self.public_key_file, 'r') as f:
        self.public_key = Crypto.PublicKey.RSA.importKey(f.read())
    else:
      self.public_key = self.private_key.publickey()
      with open(self.public_key_file, 'w') as f:
        f.write(self.public_key.exportKey())
      
    self.x509_cert_file = os.path.join(self.own_keys_directory, 'x509.pem')
    if not os.path.isfile(self.x509_cert_file):
      # Use OpenSSL's CLI to generate an X.509 from the existing RSA private key
      # Adapted from http://stackoverflow.com/a/12921889 and http://stackoverflow.com/a/12921889
      subprocess.check_call('openssl req -new -batch -x509 -nodes -days 3650 -key ' +
                            self.private_key_file +
                            ' -out ' + self.x509_cert_file,
                            shell=True)
          

  # TODO: De-uglify
  # FIXME: PyDoc
  # Use a file to permanently store certain metadata.
  def load_metadata_file(self):
    """
    Load the metadata into the workspace. If neither a metadata file nor
    backup file exists, then produce a metadata file. Finally, update
    the metadata.
    """
    # Create a null metadata object to update against
    self._metadata = Metadata(None, None, None, None, None, None, None)
    
    self.metadata_file = os.path.join(self.config_directory, 'metadata_file.pickle')
    self.backup_metadata_file = self.metadata_file + '.bak'

    try:
      # Load the metadata file
      if os.path.isfile(self.metadata_file):
        self.debug_print( (2,'Metadata file found, loading.') )
        with open(self.metadata_file, 'r') as f:
          metadata = cPickle.load(f)
      else:
        raise Exception()
    except:
      try:
        self.debug_print( (2,'Metadata file not found. Attempting to load backup.') )
        # Load the backup file
        if os.path.isfile(self.backup_metadata_file):
          self.debug_print( (2,'Backup metadata file found, loading.') )
          with open(self.backup_metadata_file, 'r') as f:
            metadata = cPickle.load(f)
            shutil.copyfile(self.backup_metadata_file, self.metadata_file)
        else:
          raise Exception()
      except:
        self.debug_print( (2,'Backup metadata file not found. Generating new file.') )        
        metadata = self.generate_initial_metadata()
        # Immediately write out to non-volatile storage since `update_metadata()` expects a pre-existing file to be made the backup.
        with open(self.metadata_file, 'w') as f:
          cPickle.dump(metadata, f)
    finally:  
      # Bring the new values into effect.
      self.update_metadata(metadata)


  def get_peer_key_path(self, peer_id):
    """
    Return the file path for the public key given the peer id.
    """
    if peer_id == self.peer_id:
      key_path = self.public_key_file
    else:
      peer_filename = self.compute_safe_filename(peer_id)
      key_path = os.path.join(self.peer_keys_directory, peer_filename+'.pem')
    return key_path
  
  def get_peer_key(self, peer_id):
    """
    Return a public key given the peer id.
    """
    if peer_id == self.peer_id:
      return self.public_key
    
    with open(self.get_peer_key_path(peer_id), 'r') as f:
      public_key = Crypto.PublicKey.RSA.importKey(f.read())
    return public_key  

  def get_store_key_path(self, store_id):
    """
    Return the file path for the public key given the store id.
    """
    if store_id == self.store_id:
      key_path = self.public_key_file
    else:
      store_filename = self.compute_safe_filename(store_id)
      key_path = os.path.join(self.store_keys_directory, store_filename+'.pem')
    return key_path
  
  def get_store_key(self, store_id):
    """
    Return a public key given the peer id.
    """
    if store_id == self.store_id:
      return self.public_key
    
    with open(self.get_store_key_path(store_id), 'r') as f:
      public_key = Crypto.PublicKey.RSA.importKey(f.read())
    return public_key
  
  def _get_store_path(self, store_id):
    """Unsafe reference to a store's absolute path meant for internals only."""
    if store_id == self.store_id:
      return self.own_store_directory
    
    store_filename = self.compute_safe_filename(store_id)
    return os.path.join(self.stores_directory, store_filename)
    
  def compute_safe_filename(self, input_string):
    return base64.urlsafe_b64encode(input_string)

  ######################
  # Metadata accessors #
  ######################
  
  @property
  def peer_id(self):
    """A quasi-unique identifier for this particular peer."""
    return self.metadata.peer_id
  
  @property
  def peer_dict(self):
    """
    A mapping from the IDs of other peers who serve as backups to this peer to 
    important metadata such as their IP address and what revisions they had for 
    stores of interest upon last contact.
    """
    return self.metadata.peer_dict
  
  @property
  def store_id(self):
    """A quasi-unique identifier for this peer's store."""
    return self.metadata.store_id
  
  @property
  def store_dict(self):
    """
    A mapping from store IDs to important metadata such as this peer's current 
    revision for the store and the IDs of peers known to be associated with the 
    store.
    """
    return self.metadata.store_dict 
  
  @property
  def merkel_tree(self):
    return self.metadata.merkel_tree
  
  @property
  def aes_key(self):
    return self.metadata.aes_key
  
  @property
  def aes_iv(self):
    return self.metadata.aes_iv
  
  # FIXME: This is returning `None` even though `self._metadata` gives the correct output.
  @property
  def metadata(self):
    """
    Important metadata about peers and stores. Access is controlled to ensure 
    that all changes are backed up to primary storage.
    """
    return self._metadata

  def get_revision_data(self, peer_id, store_id):
    """
    Return the revision data given a peer id and store id.
    """
    revision_data = self.peer_dict[peer_id].store_revisions[store_id]
    return revision_data

  #####################
  # Metadata mutators #
  #####################
  
  # Trying out weaving a lock through these calls (akin to priority inversion)
  #  so only one thread can access the metadata at a time. Hope it works.

  def update_metadata(self, metadata, lock_acquired=False):
    """
    All updates to a peer's stored metadata occur through this function so
    we can ensure that changes are backed up to primary storage before coming 
    into effect.
    """
    # Make sure we have the lock before proceeding
#     if not lock_acquired:
#       self.lock.acquire()
    
    # Only update if necessary.
    if metadata == self.metadata:
      self.debug_print( (2, 'No new metadata; update skipped.') )
      return
    
    # Accumulate and squawk out reports of changes.
    print_tuples = [(2, 'Updating metadata configuration.')]
    if metadata.peer_id != self.peer_id:
      print_tuples.append( (2, 'peer_id = {}'.format([metadata.peer_id])) )
    if metadata.peer_dict != self.peer_dict:
      print_tuples.append( (2, '`peer_dict` updated') )
      print_tuples.append( (3, 'peer_dict = {}'.format(metadata.peer_dict)) )
    if metadata.store_id != self.store_id:
      print_tuples.append( (2, 'store_id = {}'.format([metadata.store_id])) )
    if metadata.store_dict != self.store_dict:
      print_tuples.append( (2, '`store_dict` updated') )
      print_tuples.append( (3, 'store_dict = {}'.format(metadata.store_dict)) )
    if metadata.aes_key != self.aes_key:
      print_tuples.append( (2, '`aes_key` updated') )
      print_tuples.append( (4, '!!!! SOOOoo INSECURE !!!!') )
      print_tuples.append( (4, 'aes_key = {}'.format([metadata.aes_key])) )
    if metadata.aes_iv != self.aes_iv:
      print_tuples.append( (2, '`aes_iv` updated') )
      print_tuples.append(  (4, '!!!! SOOOoo INSECURE !!!!') )
      print_tuples.append( (4, 'aes_iv = {}'.format([metadata.aes_iv])) )
    if metadata.merkel_tree != self.merkel_tree:
      print_tuples.append( (2, '`merkel_tree` updated') )
      print_tuples.append( (4, 'merkel_tree:') )
      
    self.debug_print( print_tuples )
    if (metadata.merkel_tree != self.merkel_tree) and (self.debug_verbosity >= 4):
        directory_merkel_tree.print_tree(self.merkel_tree)
    
    # Copy the previous metadata file to the backup location.
    shutil.copyfile(self.metadata_file, self.backup_metadata_file)
    
    # Write the new metadata to primary storage.
    with open(self.metadata_file, 'w') as f:
      cPickle.dump(metadata, f)
    
    # Refer to the new metadata now that it's been stored to disk
    self._metadata = metadata
    
    # Release the lock if we personally acquired it
#     if not lock_acquired:
#       self.lock.release()
    
    
#   # FIXME: Would want similar functionality for server requested associations
#   def record_store_association(self, peer_id, store_id, lock=False):
#     """
#     Permanently record the list of stores that other peers are associated
#     with. Also, if the connecting peer is a backup for a store that this peer is
#     also a backup for, update that store's metadata accordingly.
#     """
#     # Do nothing if this peer's associations were already known
#     if (store_id in self.store_dict.keys()) and \
#         (peer_id in self.store_dict[store_id].peers) and \
#         (peer_id in self.peer_dict.keys()) and \
#         (store_id in self.peer_dict[peer_id].stores):
#       return
#     
#     # Make sure we have the lock before proceeding
#     if not lock:
#       self.lock.acquire()
#       lock = True
#     
#     self.debug_print( [(1, 'Recording new store association.'), 
#                        (2, 'peer_id = ' + peer_id + ', store_id=' + store_id)])
#     
#     # Create a copy of the peer metadata to stage the new changes.
#     peer_dict = self.peer_dict.copy()
#     peer_dict[peer_id].stores.add(store_id)
#     
#     # Create a copy of the store metadata to stage the new changes.
#     store_dict = self.store_dict.copy()
#     
#     # Creating a new store
#     if store_id not in self.store_dict.keys():
#       store_data = StoreData(0, set()) # FIXME: Will need actual revision number format rather than `0`.
#     # The previously known store only needs to be amended.
#     else:
#       store_data = copy.deepcopy(self.store_dict[store_id]) # Named tuples (and tuples in general) require deep copying... I think.
#     store_data.peers.add(peer_id)
#     # FIXME: Will also want to record this peer's revision number.
#     store_dict[store_id] = store_data
#     
#     metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict)
#     self.update_metadata(metadata)


  def record_peer_data(self, peer_id, peer_data, lock_acquired=False):
    """
    Update the recorded metadata for an individual peer.
    """
    # Make sure we have the lock before proceeding
#     if not lock_acquired:
#       self.lock.acquire()
    
    peer_mutual_stores = set(peer_data.store_revisions.keys()).intersection(set(self.store_dict.keys()))
    # Only want to track peers that are associated with at least one store we're concerned with.
    if not peer_mutual_stores:
      return
    
    # Only want new data.
    if (peer_id in self.peer_dict.keys()) and (peer_data == self.peer_dict[peer_id]):
      return
    
    # Create copies data for staging changes.
    peer_dict = copy.deepcopy(self.peer_dict)
    store_dict = copy.deepcopy(self.store_dict)
    
    # Prepare an empty record if the peer wasn't already known.
    if not (peer_id in self.peer_dict.keys()):
      ip_address = None
      store_revisions = dict()
    # Otherwise, work from existing knowledge of the peer.
    else:
      ip_address = peer_dict[peer_id].ip_address
      store_revisions = peer_dict[peer_id].store_revisions
      
    # Record the peer's associations with only the stores we care about.
    for mutual_store_id in peer_mutual_stores:
      # Verify the reported revision data before recording.
      if self.verify_revision_data(mutual_store_id, peer_data.store_revisions[mutual_store_id]):
        store_revisions[mutual_store_id] = peer_data.store_revisions[mutual_store_id]
      else:
        store_revisions[mutual_store_id] = INVALID_REVISION
      # Simultaneously ensure the store's association with the peer to maintain the bidirectional mapping.
      store_dict[mutual_store_id].peers.add(peer_id) 
    
    # FIXME
    # Again, peers are unaware of their own IP addresses, so only take valid changes thereof
    if peer_data.ip_address:
      ip_address = peer_data.ip_address
    
    # Enact the update.
    peer_dict[peer_id] = PeerData(ip_address, store_revisions)
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict, self.aes_key, self.aes_iv, self.merkel_tree)
    self.update_metadata(metadata, True)

    # Release the lock if we personally acquired it
#     if not lock_acquired:
#       self.lock.release()
      
  
  def learn_peer_gossip(self, gossip_peer_dict, lock=False):
    """
    Update our knowledge of peers based on gossip from another peer.
    """
    # Thoroughly checked. (besides locking)
    
    # Make sure we have the lock before proceeding
#     if not lock:
#       self.lock.acquire()
    
    # Limit our considerations to mutual peers.
    mutual_peers = set(gossip_peer_dict.keys()).intersection(set(self.peer_dict.keys()))

    our_stores = set(self.store_dict.keys())
    
    for peer_id in mutual_peers:
      # Only update if information about received about a peer is newer than our 
      #  records. Currently, the ways of detecting this are somewhat indirect. 
      
      # TODO: Without signing `PeerData` objects, malicious peers 
      #  can manipulate the state of another peer. (versioning too?)
      
      gossip_peer_stores = set(gossip_peer_dict[peer_id].store_revisions.keys())
      recorded_peer_stores = set(self.peer_dict[peer_id].store_revisions.keys())
      
      # See if the gossip indicates the peer is newly associated with a store we also have.
      if gossip_peer_stores.intersection(our_stores).difference(recorded_peer_stores):
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
        break
      
      
      # See if the gossip reports the peer to be more current with any mutual 
      #  store than we knew about.
      
      peer_mutual_stores = gossip_peer_stores.intersection(our_stores)

      gossip_peer_revision_data = gossip_peer_dict[peer_id].store_revisions
      recorded_peer_revision_data = self.peer_dict[peer_id].store_revisions
      gossip_revisions = [gossip_peer_revision_data[store_id] for store_id in peer_mutual_stores]
      recorded_revisions = [recorded_peer_revision_data[store_id] for store_id in peer_mutual_stores]

      if any( self.gt_revision_data(s_id, g_rev, r_rev) \
              for s_id, g_rev, r_rev in zip(peer_mutual_stores, gossip_revisions, recorded_revisions) ):
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
        break
    
    # Learn new peers associated with our stores of interest.
    unknown_peers = set(gossip_peer_dict.keys()).difference(set(self.peer_dict.keys()))
    for peer_id in unknown_peers:
      gossip_peer_stores = set(gossip_peer_dict[peer_id].store_revisions.keys())
      if set(gossip_peer_stores).intersection(our_stores):
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
    
    # Release the lock if we personally acquired it
#     if not lock:
#       self.lock.release()
    
    
  def update_ip_address(self, lock=False):
    """Update this peer's already existing IP address data."""
    # Make sure we have the lock before proceeding
    if not lock:
      self.lock.acquire()
    
    # Create staging copy of data to be changed
    peer_dict = copy.deepcopy(self.peer_dict)
    
    # Get and store the IP address
    # FIXME: Would like to sign this data (probably the whole `PeerData` object).
    ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin']
    peer_data = PeerData(ip_address, peer_dict[self.peer_id].store_revisions)
    peer_dict[self.peer_id] = peer_data
    
    # Enact the change.
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, self.store_dict, self.aes_key, self.aes_iv, self.merkel_tree)
    self.update_metadata(metadata, True)
    
    # Release the lock if we personally acquired it
#     if not lock:
#       self.lock.release()
    
    
  def update_peer_revision(self, peer_id, store_id, invalid=False, lock=None):
    """
    After sending a peer synchronization data and verifying their store contents, 
    update our recording of their revision for the store in question to match 
    ours.
    """
    # Make sure we have the lock before proceeding
#     if not lock:
#       self.lock.acquire()
    
    # If the peer had a more recent revision than us, no need to update.
    our_revision = self.get_revision_data(self.peer_id, store_id)
    their_revision = self.get_revision_data(peer_id, store_id)
    if self.gt_revision_data(store_id, their_revision, our_revision):
      return
    
    # Create a copy of the pertinent data in which to stage our changes.
    peer_store_revisions = copy.deepcopy(self.peer_dict[peer_id].store_revisions)
    
    if not invalid:
      # Set the peer's revision for the store to match ours.
      self.debug_print( (1, 'Syncing peer is now at revision {}'.format(self.store_dict[store_id].revision_data.revision_number)) )
      peer_store_revisions[store_id] = self.store_dict[store_id].revision_data
    else:
      # Record the peer's revision for the store as `None`
      peer_store_revisions[store_id] = INVALID_REVISION
    
    # Enact the changes
    peer_data = PeerData(self.peer_dict[peer_id].ip_address, peer_store_revisions)
    self.record_peer_data(peer_id, peer_data, True)

    # Release the lock if we personally acquired it
#     if not lock:
#       self.lock.release()
    
    
  def update_own_store_revision(self, store_id, revision_data, lock=None):
    """
    Update the store dictionary for a given store id with new revision data.
    """
    # Make sure we have the lock before proceeding
#     if not lock:
#       self.lock.acquire()
    
    # Create a copy of the pertinent data in which to stage our changes.
    store_dict = copy.deepcopy(self.store_dict)
    store_dict[store_id] = StoreData(revision_data=revision_data, peers=store_dict[store_id].peers.union(set([self.peer_id])))
    
    # Also modify our own entry in the peer dictionary so we can gossip to other peers about the new revision.
    ip_address = self.peer_dict[self.peer_id].ip_address
    store_revisions = copy.deepcopy(self.peer_dict[self.peer_id].store_revisions)
    store_revisions[store_id] = revision_data
    peer_data = PeerData(ip_address, store_revisions)
    self.record_peer_data(self.peer_id, peer_data)
    
    # Enact the change
    metadata = Metadata(self.peer_id, self.peer_dict, self.store_id, store_dict, self.aes_key, self.aes_iv, self.merkel_tree)
    self.update_metadata(metadata, True)
    
    # Release the lock if we personally acquired it
#     if not lock:
#       self.lock.release()
    
    
  def check_store(self):
    """
    Check this peer's own store for changes generating new revision data and a 
    new Merkel tree upon updates.
    """
    # Compute new Merkel tree from scratch.
    new_merkel_tree = directory_merkel_tree.make_dmt(self.own_store_directory, encrypter=self)
    if (self.merkel_tree) and (self.merkel_tree == new_merkel_tree):
      return
    
    if (self.store_dict[self.store_id].revision_data == INVALID_REVISION):
      revision_number = 1
    else:
      revision_number = self.store_dict[self.store_id].revision_data.revision_number + 1
        
    # Our store has changed so get, sign, and record the new revision data.
    store_hash = new_merkel_tree.dmt_hash
    pickled_payload = cPickle.dumps( (revision_number, store_hash) )
    signature = self.sign(pickled_payload)
    
    # Update our revision data for this store (and for our association to it).
    revision_data = RevisionData(revision_number=revision_number, store_hash=store_hash, signature=signature)
    self.update_own_store_revision(self.store_id, revision_data)
    
    # Also store the new Merkel tree.
    metadata = Metadata(self.peer_id, self.peer_dict, self.store_id, self.store_dict, self.aes_key, self.aes_iv, new_merkel_tree)
    self.update_metadata(metadata)
    
    self.debug_print( (1, 'Change detected in own store. New signed revision number: {}'.format(revision_number)) )
    
    
  def store_put_item(self, store_id, relative_path, file_contents=None):
    """
    Store data to the gen relative path for a store id.
    """
    if relative_path[-1] == '/':
      isdir = True
    else:
      isdir = False
      
    if store_id == self.store_id:
      # Undo the path encryption done while creating our Merkel tree.
      relative_path = self.decrypt_own_store_path(relative_path)
      self.debug_print( [(2, 'relative_path (decrypted) = {}'.format(relative_path))] )
      # If a file, decrypt the contents
      if not isdir:
        file_contents = self.decrypt(file_contents)
        self.debug_print( [(5, 'file_contents (decrypted) = {}'.format(file_contents))] )
        
            
    path = os.path.join(self._get_store_path(store_id), relative_path)
    
    if isdir:
      self.debug_print( [(1, 'Writing directory to store.')] )
#                          (2, 'store_id = {}'.format(store_id))
#                          (2, 'relative_path = {}'.format(relative_path))])
      if not os.path.exists(path):
        os.makedirs(path)
    else:
      # Create subdirectory levels as needed.
      file_directory = os.path.dirname(path)
      if not os.path.isdir(file_directory):
        os.makedirs(file_directory)
      
      self.debug_print( [(1, 'Writing file to store.')] )
#                          (2, 'store_id = {}'.format(store_id))
#                          (2, 'relative_path = {}'.format(relative_path)),
#                          (5, 'file_contents:'),
#                          (5, file_contents)])
           
      with open(path, 'w') as f:
        f.write(file_contents)
        
  def store_delete_item(self, store_id, relative_path):
    """
    Delete data at the given relative path for a store id
    """
    if store_id == self.store_id:
      # Undo the path encryption done while creating our Merkel tree.
      relative_path = self.decrypt_own_store_path(relative_path)
      self.debug_print( [(2, 'relative_path (decrypted) = {}'.format(relative_path))] )
      
    path = os.path.join(self._get_store_path(store_id), relative_path)
    
    if os.path.isfile(path):
      self.debug_print( (1, 'Deleting file from store.') )
      os.remove(path)
    elif os.path.isdir(path):
      self.debug_print( (1, 'Deleting directory (and contents) from store.') )
      # Note that this deletes the non-empty directories, so depending on the 
      #  ordering of delete items we might preemptively delete files or folders
      #  that still have pending delete requests.
      shutil.rmtree(path)
      
   

  def decrypt_own_store_path(self, encrypted_relative_path):
    """
    Take a given encrypted relative path and decrypt it directory by directory
    """
    print_tuples = [ (1, 'DEBUG: Decrypting path: {}'.format(encrypted_relative_path)) ]
    
    encrypted_path_elements = encrypted_relative_path.split('/')
    decrypted_path_elements = [self.decrypt_filename(e) for e in encrypted_path_elements]
    decrypted_relative_path = '/'.join(decrypted_path_elements)
    
    print_tuples.append( (1, 'DEBUG: Decrypted to: {}'.format(decrypted_relative_path)) )
    self.debug_print(print_tuples)
    
    return decrypted_relative_path


  def store_get_item_contents(self, store_id, relative_path):
    """
    Take a store id and relative path and return the contents of the file.
    Make sure contents are encrypted if they are you own files.
    """
    # Directory
    if relative_path[-1] == '/':
      return None
    if store_id == self.store_id:
      # Undo the path encryption done while creating our Merkel tree.
      relative_path = self.decrypt_own_store_path(relative_path)
    
    path = os.path.join(self._get_store_path(store_id), relative_path)
    
    with open(path, 'r') as f:
      file_contents = f.read()
      
    if store_id == self.store_id:
      file_contents = self.encrypt(file_contents)
    
    return file_contents
  
  
#   def store_is_file(self, store_id, relative_path):
#     if store_id == self.store_id:
#       # Undo the path encryption done while creating our Merkel tree.
#       relative_path = self.decrypt_own_store_path(relative_path)
#     
#     path = os.path.join(self._get_store_path(store_id), relative_path)
#     
#     return os.path.isfile(path)
#     
#     
#   def store_is_dir(self, store_id, relative_path):
#     if store_id == self.store_id:
#       # Undo the path encryption done while creating our Merkel tree.
#       relative_path = self.decrypt_own_store_path(relative_path)
#     
#     path = os.path.join(self._get_store_path(store_id), relative_path)
#     
#     return os.path.isdir(path)
#     
#   def store_makedirs(self, store_id, relative_path):
#     if store_id == self.store_id:
#       # Undo the path encryption done while creating our Merkel tree.
#       relative_path = self.decrypt_own_store_path(relative_path)
#     
#     path = os.path.join(self._get_store_path(store_id), relative_path)
#     
#     os.makedirs(path)
  
  
  #########################
  # Cryptographic methods #
  #########################
  
  def record_peer_pubkey(self, peer_id, peer_public_key_string):
    """
    Used to record a peer's public key upon first encounter. The key is 
    subsequently used to verify SSL connections and signatures.
    """
    with open(self.get_peer_key_path(peer_id), 'w') as f:
      f.write(peer_public_key_string)


  def record_store_pubkey(self, store_id, store_public_key_string):
    """
    Used to record a store's public key upon association. The key is 
    subsequently used for signature verification.
    """
    # NOTE: This is identical to the above function for peers, but affords the flexibility to quickly change the implementation later.
    with open(self.get_store_key_path(store_id), 'w') as f:
      f.write(store_public_key_string)

    
  def gt_revision_data(self, store_id, revision_data_1, revision_data_2):
    """
    Returns `True` if `revision_data_1` passes signature verification and either 
    is later than `revision_data_2` or that revision fails signature verification.
    """
    # Thoroughly checked.
    
    if not self.verify_revision_data(store_id, revision_data_1):
      return False
    
    if not self.verify_revision_data(store_id, revision_data_2):
      return True
    
    return revision_data_1.revision_number > revision_data_2.revision_number

  
  def verify_revision_data(self, store_id, revision_data):
    """
    Verify the signature of a received revision number.
    """
    # Thoroughly checked.
    
    if (revision_data == INVALID_REVISION) or (not revision_data.signature):
      return False
    
    pickled_payload = cPickle.dumps( (revision_data.revision_number, revision_data.store_hash) )
    
    return self.verify(store_id, revision_data.signature, pickled_payload)
  
  
  def sign_revision(self, revision_number, store_hash):
    """
    Take a revision number and store hash and return a RevisionData object
    containing a revision number, store hash, and signature for the two.
    """
    # Thoroughly checked.
    
    # Pickle and sign the revision data
    pickled_payload = cPickle.dumps( (revision_number, store_hash) )
    signature = self.sign(pickled_payload)
    signed_revision_data = RevisionData(revision_number=revision_number, store_hash=store_hash, signature=signature)
    return signed_revision_data
  
  
  def get_merkel_tree(self, store_id, nonce=None):
    """
    Get the locally computed Merkel tree for a store.
    """
    # Own store without nonce
    if (store_id == self.store_id) and (not nonce):
      return self.merkel_tree
    
    elif store_id == self.store_id:
      # Compute a new encrypted, potentially nonced Merkel tree of our own store.
      merkel_tree = directory_merkel_tree.make_dmt(self._get_store_path(store_id), nonce=nonce, encrypter=self)
    else:
      # Make the Merkel tree.
      merkel_tree = directory_merkel_tree.make_dmt(self._get_store_path(store_id), nonce=nonce)
    
    return merkel_tree
    

  def diff_store_to_merkel_tree(self, store_id, mt_old):
    """
    Compute the difference between the current contents of the specified store 
    and those indicated by the older, provided Merkel tree.
    """
    mt_new = self.get_merkel_tree(store_id)
    
    updated, new, deleted = directory_merkel_tree.compute_tree_changes(mt_new, mt_old)
    
    return updated.union(new), deleted
    
  def get_store_hash(self, store_id, nonce=''):
    """
    Get the hash for a given store id.
    """
    merkel_tree = self.get_merkel_tree(store_id, nonce)
    return merkel_tree.dmt_hash
    
  def verify_sync(self, peer_id, store_id):
    """
    Check our newly syncronized store against the signed revision data that the 
    sync sender passed us.
    """
    
    peer_revision_data = self.peer_dict[peer_id].store_revisions[store_id]
    
    # The revision data's signature doesn't verify (we synced to a bad backup).
    if not self.verify_revision_data(store_id, peer_revision_data):
      self.debug_print( (1, 'WARNING: Synced to an invalid revision. Checks should have prevented this.') )
      self.update_own_store_revision(store_id, INVALID_REVISION)
      return False
    
    calculated_hash = self.get_store_hash(store_id)
    signed_hash = peer_revision_data.store_hash
    
    # We successfully synced.
    if calculated_hash == signed_hash:
      self.debug_print( [(1, 'New store contents verified by peer\'s signed revision data.'),
                         (1, 'Updating our revision data to signed revision {}.'.format(peer_revision_data.revision_number))] )
      self.update_own_store_revision(store_id, peer_revision_data)
      return True
      
    # The sync failed.
    else:
      self.debug_print( (1, 'New store contents could not be verified by peer\'s signed revision data. Marking our revision as invalid.') )
      self.update_own_store_revision(store_id, INVALID_REVISION)
      return False
      
  def increment_revision(self):
    """
    Create and record new revision data for the peer's own store.
    """
    
    self.debug_print( (1, 'Incrementing the local store\'s revision data.') )
    
    # Increment up from the current revision number
    revision_number = self.store_dict[self.store_id].revision_data.revision_number + 1
    
    # Recalculate the store's hash
    store_hash = self.get_store_hash(self.store_id)
    
    
    # Enact the change
    revision_data = self.sign_revision(revision_number, store_hash)
    self.update_own_store_revision(self.store_id, revision_data)
    
  def sign(self, payload):
    """
    Produce a signature for the given paylod using a user's private region.
    """
    # Thoroughly checked.
    
    payload_hash = Crypto.Hash.SHA256.new(payload)
    signature = Crypto.Signature.PKCS1_v1_5.new(self.private_key).sign(payload_hash)
    return signature
  
  def verify(self, store_id, signature, payload):
    """
    Given a store id, a payload, and a signature for a payload, verify the
    signature.
    """
    # Thoroughly checked.
    
    public_key = self.get_store_key(store_id)
    payload_hash = Crypto.Hash.SHA256.new(payload)
    
    return Crypto.Signature.PKCS1_v1_5.new(public_key).verify(payload_hash, signature)
  
  def encrypt(self, plaintext):
    """
    Given a plaintext, use personal AES key to encrypt the plaintext.
    """
    # Have to reuse the IV because we're encrypting on the fly and need to be able to compare Merkel trees... vuln?
    cipher = Crypto.Cipher.AES.new(self.aes_key, Crypto.Cipher.AES.MODE_CFB, self.aes_iv)
    ciphertext = self.aes_iv + cipher.encrypt(plaintext)
    return ciphertext
    
  def decrypt(self, ciphertext):
    """
    Decrypt a ciphertext given using the personal AES key.
    """
    aes_iv = ciphertext[:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.new(self.aes_key, Crypto.Cipher.AES.MODE_CFB, aes_iv)
    plaintext = cipher.decrypt(ciphertext)[Crypto.Cipher.AES.block_size:]
    return plaintext

  def encrypt_filename(self, filename):
    """
    Take a filename and return an encryption the filename safe to use.
    """
    encrypted_filename = self.encrypt(filename)
    return self.compute_safe_filename(encrypted_filename)
  
  def decrypt_filename(self, safe_encrypted_filename):
    """
    Take a safe encrypted filename and return the original filename from which
    the encrypted filename was produced.
    """
    encrypted_filename = base64.urlsafe_b64decode(safe_encrypted_filename)
    filename = self.decrypt(encrypted_filename)
    return filename
   
  #########################
  # Communication helpers #
  #########################
  
  def connect_to_peer(self, peer_id, timeout=5):
    """
    Connect to a peer given a peer id and return the connection.
    """
    # TODO: Raises `KeyError` exception on invalid UUID.
    peer_ip = self.peer_dict[peer_id].ip_address
    # FIXME: Want to verify peer server's public key
    skt = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_SSLv3)
    skt.settimeout(timeout)
    skt.connect((peer_ip, self.listening_port))
    return skt
  
  
  def create_listening_socket(self, timeout=5):
    """
    Produce a socket to listen to other peers attempting to connect.
    """
    skt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    skt.settimeout(timeout)
    skt.bind(('', self.listening_port))
    skt.listen(1) # FIXME
    return skt
  
  
  def select_sync_store(self, peer_id):
    """
    Select which of a peer server's stores to sync with.
    """
    # Get the communicating peer server's list of stores and respective revision data.
    peer_store_revisions = self.peer_dict[peer_id].store_revisions
    
    # Only interested in stores the peer also has.
    # FIXME: I don't think the mutuality check is necessary anymore...
    mutual_stores = set(peer_store_revisions.keys())
    
    potential_stores = set()
    
    # Consider stores which the peer server has a later revision for.
    for store_id in mutual_stores:
      if self.gt_revision_data(store_id, peer_store_revisions[store_id], self.store_dict[store_id].revision_data):
        potential_stores.add(store_id)
        
    # If the peer server doesn't have any updates for us, consider updates we have for them.
    if not potential_stores:
      for store_id in mutual_stores:
        if self.gt_revision_data(store_id, self.store_dict[store_id].revision_data, peer_store_revisions[store_id]):
          potential_stores.add(store_id)
    
    # If we are both at the same revision for all mutual stores, we will verify one another's revision for some mutual store.
    if not potential_stores:
      # Only consider the mutual stores for which both ends have a valid revision.
      for store_id in mutual_stores:
        our_revision = self.store_dict[store_id].revision_data
        their_revision = peer_store_revisions[store_id]
        if self.verify_revision_data(store_id, our_revision) and self.verify_revision_data(store_id, their_revision):
          potential_stores.add(store_id)

    # Return `None` if we couldn't find a store to sync.
    if not potential_stores and (not mutual_stores):
      return None
    elif not potential_stores:
      return mutual_stores
    # Otherwise, choose a random store from the determined options.
    return random.sample(potential_stores, 1)[0]
  
  
  def select_sync_peer(self):
    """
    Select which peer to sync with.
    """
    other_peers = set(self.peer_dict.keys()).difference(set([self.peer_id]))
    potential_peers = set()
    
    # Compile a set of peers who (reportedly) have newer revisions of our stores.
    for peer_id in other_peers:
      peer_store_revisions = self.peer_dict[peer_id].store_revisions
      for store_id in peer_store_revisions.keys():
        if self.gt_revision_data(store_id, peer_store_revisions[store_id], self.store_dict[store_id].revision_data):
          potential_peers.add(peer_id)
          # No need to check the revision data for this peer's other synced stores
          break
    
    # If no peers have newer revisions for us, compile peers for whom we have newer revisions
    if not potential_peers:
      for peer_id in other_peers:
        peer_store_revisions = self.peer_dict[peer_id].store_revisions
        for store_id in peer_store_revisions.keys():
          if self.gt_revision_data(store_id, self.store_dict[store_id].revision_data, peer_store_revisions[store_id]):
            potential_peers.add(peer_id)
            # No need to check the revision data for this peer's other synced stores
            break
    
    # Otherwise, consider any peer with whom we share a valid revision.
    if not potential_peers:
      for peer_id in other_peers:
        peer_store_revisions = self.peer_dict[peer_id].store_revisions
        for store_id in peer_store_revisions.keys():
          if self.store_dict[store_id].revision_data and peer_store_revisions[store_id]:
            potential_peers.add(peer_id)
            # No need to check the revision data for this peer's other synced stores
            break
    
    # Return `None` if we couldn't find a peer to sync with.
    if (not potential_peers) and other_peers:
      return random.sample(other_peers, 1)[0]
    elif not potential_peers:
      return None
    # Otherwise, choose a random store from the determined options.
    return random.sample(potential_peers, 1)[0]
  
  
  def determine_sync_type(self, peer_id, store_id):
    """
    Figure out what type of synchronization (send, receive, or check) we'll be 
    participating in.
    """
    # Get the communicating peer server's list of stores and respective revision data.
    our_revision = self.store_dict[store_id].revision_data
    peer_revision = self.peer_dict[peer_id].store_revisions[store_id]
    
    # Communicating peer has a newer revision of the store than us.
    if self.gt_revision_data(store_id, peer_revision, our_revision):
      return 'receive'
    
    # We have a newer revision of the store than the communicating peer.
    if self.gt_revision_data(store_id, our_revision, peer_revision):
      return 'send'
    
    # If neither the communicating peer nor we have a valid revision for the store, raise an exception.
    if (not our_revision) and (not peer_revision):
      # FIXME: Raise a meaningful exception.
      raise Exception()
    
    # Otherwise, we both have the same (valid) revision.
    return 'check'


  def sync_receive(self, skt, sender_peer_id, sync_store_id):
    """
    Conduct a sync as the receiving party.
    """
    # Submit our Merkel tree for the store so the sync sender can identify which files require modification.
    merkel_tree = self.get_merkel_tree(sync_store_id)
    self.debug_print( [(1, 'Sending Merkel tree to sync sender.'),
                       (4, 'merkel_tree :')] )
    if self.debug_verbosity >= 4:
      directory_merkel_tree.print_tree(merkel_tree)
    self.send_merkel_tree_msg(skt, sync_store_id, merkel_tree)   
    
    # Get and process all commands to update/create and delete files before proceeding to verification.
    self.debug_print( (1, 'Processing update and delete commands from sync sender as they arrive.') )
    
    self.debug_print( (2, 'Waiting for sync command from sync sender.') )
    message_id, pickled_payload = self.receive(skt)
    while message_id in {message_ids['update_file_msg'], message_ids['delete_file_msg']}:
      # Update/create a file.
      if (message_id == message_ids['update_file_msg']):
        relative_path, file_contents = self.unpickle('update_file_msg', pickled_payload)
        self.debug_print( [(1, 'Received update action from sync sender.'),
                           (2, 'relative_path = {}'.format(relative_path)),
                           (5, 'file_contents:'),
                           (5, file_contents)])
        self.store_put_item(sync_store_id, relative_path, file_contents)

      # Delete a file or directory.
      elif (message_id == message_ids['delete_file_msg']):
        relative_path = self.unpickle('delete_file_msg', pickled_payload)
        self.debug_print( [(1, 'Received delete action from sync sender.'),
                           (2, 'relative_path = {}'.format(relative_path))] )
        self.store_delete_item(sync_store_id, relative_path)
        
      # Get the next message.
      self.debug_print( (2, 'Waiting for sync command from sync sender.') )
      message_id, pickled_payload = self.receive(skt)
      
    # Verify that the sync sender has signaled the end of the sync. 
    if message_id != message_ids['sync_complete_msg']:
      self.handle_unexpected_message(message_id, pickled_payload)
      self.debug_print( (1, 'Sync receive aborted due to messaging errors. Marking our copy of the store as invalid and disconnecting.') )
      self.update_own_store_revision(sync_store_id, INVALID_REVISION)
      self.send_disconnect_req(skt, 'Messaging errors during sync receipt.')
      raise ManualDisconnectException()
    
    self.debug_print( (1, 'Received sync complete message from sync sender.') )
    
    # Participate in the post-sync check.
    self.debug_print( (1, 'Sync data transfer complete. Proceeding to cooperative verification.') )
    self.sync_check(skt, sender_peer_id, sync_store_id)
    
    # Locally verify the sync based on the signed revision data that we have recorded 
    #  for the sync sender and update our revision number accordingly.
    if not self.verify_sync(sender_peer_id, sync_store_id):
      self.debug_print( (1, 'Local sync verification failed. Marking our copy of the store as invalid and disconnecting.') )
      self.send_disconnect_req(skt, 'Local sync verification failed.')
      raise ManualDisconnectException()
    
    
  def sync_send(self, skt, receiver_peer_id, sync_store_id):
    """
    Conduct a sync as the sending party.
    """
    # Receive the sync receiver's Merkel tree for the store.
    self.debug_print( (2, 'Waiting for Merkel tree from sync receiver.') )
    pickled_payload = self.receive_expected_message(skt, 'merkel_tree_msg')
    merkel_tree = self.unpickle('merkel_tree_msg', pickled_payload)
    self.debug_print( [(1, 'Received merkel tree to sync receiver.'),
                       (4, 'merkel_tree :')] )
    if self.debug_verbosity >= 4:
      directory_merkel_tree.print_tree(merkel_tree)
    
    updated_files, deleted_files = self.diff_store_to_merkel_tree(sync_store_id, merkel_tree)
    self.debug_print( [(2, 'updated_files = {}'.format(updated_files)),
                       (2, 'deleted_files = {}'.format(deleted_files))])
    
    # Send the sync receiver each file that has changed
    for relative_path in updated_files:
      # Read in the file's contents
      file_contents = self.store_get_item_contents(sync_store_id, relative_path)
      
      # Send the file updates to the communicating peer.
      self.debug_print( [(1, 'Sending update action to sync receiver.'),
                         (2, 'relative_path = {}'.format(relative_path)),
                         (5, 'file_contents:'),
                         (5, file_contents)])
      self.send_update_file_msg(skt, relative_path, file_contents)
      
    # Inform the sync receiver of each file that has been deleted
    for relative_path in deleted_files:
      self.debug_print( [(1, 'Sending delete action to sync receiver.'),
                         (2, 'relative_path = {}'.format(relative_path))] )
      self.send_delete_file_msg(skt, relative_path)
      
    self.debug_print( (1, 'Sending sync complete message to sync sender.') )
    self.send_sync_complete_msg(skt)
    
    # Check that the sync receiver's store is correctly up to date with ours and record the new revision data accordingly.
    self.debug_print( (1, 'Sync data transfer complete. Proceeding to cooperative verification.') )
    self.sync_check(skt, receiver_peer_id, sync_store_id)
    

  def sync_check(self, skt, sync_peer_id, sync_store_id):
    """
    Verify the other peer's store data.
    """
    # Generate a nonce for verifying the peer's store.
    generated_nonce = str(random.SystemRandom().random())
    self.debug_print( [(1, 'Sending sync verification request to peer.'),
                       (2, 'generated_nonce = {}'.format([generated_nonce]))] )
    self.send_verify_sync_req(skt, generated_nonce)
    
    # The peer should simultaneously send a verification request of their own, so receive it
    self.debug_print( (2, 'Waiting for peer\'s sync verification request.') )
    pickled_payload = self.receive_expected_message(skt, 'verify_sync_req')
    received_nonce = self.unpickle('verify_sync_req', pickled_payload)
    self.debug_print( [(1, 'Received sync verification request from peer.'),
                       (2, 'received_nonce = {}'.format([received_nonce]))] )    

    # Calculate the nonced hash as requested and respond to the peer.
    requested_verification_hash = self.get_store_hash(sync_store_id, received_nonce)
    self.debug_print( [(1, 'Sending sync verification response to peer.'),
                       (2, 'requested_verification_hash = {}'.format([requested_verification_hash]))] )    
    self.send_verify_sync_resp(skt, requested_verification_hash)
    
    # Receive the peer's verification response.
    self.debug_print( (2, 'Waiting for peer\'s sync verification response.') )
    pickled_payload = self.receive_expected_message(skt, 'verify_sync_resp')
    received_verification_hash = self.unpickle('verify_sync_resp', pickled_payload)
    self.debug_print( [(1, 'Received sync verification response from peer.'),
                       (2, 'received_verification_hash = {}'.format([received_verification_hash]))] )    
    
    # Now generate our own nonced hash of the store to check the peer's response against.
    generated_hash = self.get_store_hash(sync_store_id, generated_nonce)
     
    # If the hashes match, the peer has verified their store contents match ours 
    #  and their recorded revision data should reflect the more recent between ours and theirs.
    if (received_verification_hash == generated_hash):
      self.debug_print( (1, 'Cooperative sync verification completed successfully.') )
      self.update_peer_revision(sync_peer_id, sync_store_id)
    
    else:
      self.debug_print( (1, 'Cooperative sync verification failed. Marking the syncing peer\'s revision for this store as invalid and disconnecting.') )
      self.update_peer_revision(sync_peer_id, sync_store_id, invalid=True)
      self.send_disconnect_req(skt, 'Cooperative sync verification failed.')
      raise ManualDisconnectException()
    
    
  ############################
  # Message dispatch methods #
  ############################
  
  def send(self, skt, message_id, message_data):
    """
    given a secure connection, message identification sting, and message data,
    pickle the data into a serializable format, and send the resulting data
    over the secure connection.
    """
    pickled_payload = cPickle.dumps(message_data)
    message_body = (message_id, pickled_payload)
    pickled_message = cPickle.dumps(message_body)
    skt.send(struct.pack('!I', len(pickled_message))+pickled_message)
    
  def send_handshake_msg(self, skt):
    """
    Send a handshake message which containing the personal peer id and
    dictionary of other known peers.
    """
    message_id = message_ids['handshake_msg']
    message_data = (self.peer_id, self.peer_dict)
    self.send(skt, message_id, message_data)
    
  def send_sync_req(self, skt, store_id):
    """
    Given a secure connection and store id, send a request to
    secure the given store id.
    """
    message_id = message_ids['sync_req']
    message_data = store_id
    self.send(skt, message_id, message_data)
    
  def send_merkel_tree_msg(self, skt, store_id, merkel_tree):
    """
    Given a secure connection, store id, and Merkle tree, send the Merkle tree
    over the secure connection.
    """
    message_id = message_ids['merkel_tree_msg']
    message_data = merkel_tree
    self.send(skt, message_id, message_data)
    
  def send_update_file_msg(self, skt, relative_path, file_contents):
    """
    Given a secure connection, relative path, and file contents, send a the
    file and file contents over the secure connection.
    """
    message_id = message_ids['update_file_msg']
    message_data = (relative_path, file_contents)
    self.send(skt, message_id, message_data)
    
  def send_delete_file_msg(self, skt, relative_path):
    """
    Given a secure connection and a relative path, send a request to delete the
    file at the given path.
    """
    message_id = message_ids['delete_file_msg']
    message_data = relative_path
    self.send(skt, message_id, message_data)
    
  def send_sync_complete_msg(self, skt):
    """
    Given a secure message, send a message signifying the completion of synced
    data.
    """
    message_id = message_ids['sync_complete_msg']
    message_data = None
    self.send(skt, message_id, message_data)
    
  def send_verify_sync_req(self, skt, nonce):
    """
    Given a secure connection and noce, send a request to verigy a synch
    with a salted Merkle tree hash.
    """
    message_id = message_ids['verify_sync_req']
    message_data = nonce
    self.send(skt, message_id, message_data)
        
  def send_verify_sync_resp(self, skt, verification_hash):
    """
    Respond to a requested synch verification with a given verification hash.
    """
    message_id = message_ids['verify_sync_resp']
    message_data = verification_hash
    self.send(skt, message_id, message_data)
        
  def send_disconnect_req(self, skt, disconnect_message):
    """
    Send a request to disconnect over a given secure connection as well as a
    given disconnect message.
    """
    message_id = message_ids['disconnect_req']
    message_data = disconnect_message
    self.send(skt, message_id, message_data)    

  def send_public_key_msg(self, skt):
    """
    send the public key over a given secure connection.
    """
    message_id = message_ids['public_key_msg']
    message_data = self.public_key.exportKey()
    self.send(skt, message_id, message_data)    

    
  ###########################
  # Message receipt methods #
  ###########################
  
  def receive(self, skt):
    """
    Low-level receipt of messages. Attempts to retrieve exact message lengths to 
    support consecutively submitted messsages.
    """ 
    # First retrieve the message header
    message_buffer = str()
    length_received = 0
    while length_received < HEADER_SIZE:
      message_buffer += skt.recv(HEADER_SIZE - length_received)
      length_received = len(message_buffer)
    
    # Unpack the header
    length = struct.unpack('!I',message_buffer[0:HEADER_SIZE])[0]
    
    # Retrieve the message body.
    while length_received < (length + HEADER_SIZE):
      message_buffer += skt.recv((length + HEADER_SIZE) - length_received)
      length_received = len(message_buffer)
    
    # Message has incorrect length.
    if len(message_buffer) != (length + HEADER_SIZE):
      # FIXME: Provide a meaningful exception.
      raise Exception()
    
    # Unpickle the message contents
    pickled_message = message_buffer[HEADER_SIZE:HEADER_SIZE+length]
    (message_id, pickled_payload) = cPickle.loads(pickled_message)
    return message_id, pickled_payload
  
  
  def receive_expected_message(self, skt, expected_message_type):
    """
    Receive a message, automatically handling situations where the message was 
    not of the type expected.
    """
    expected_message_id = message_ids[expected_message_type]
    
    message_id, pickled_payload = self.receive(skt)
    if message_id != expected_message_id:
      self.handle_unexpected_message(message_id, pickled_payload)
      # FIXME: Use a more specific exception.
      raise Exception()
    return pickled_payload
    
    
  def handle_unexpected_message(self, message_id, pickled_payload):
    """
    Respond to an unexpected message id and payload, currently through
    either responding to a disconnect request or printing the unknown
    message.
    """
    if message_id == message_ids['disconnect_req']:
      # Unpickle message data from `'disconnect_req'` message type.
      disconnect_message = self.unpickle('disconnect_req', pickled_payload)
      self.debug_print( [(1, 'Peer requested disconnect, reporting the following:'),
                         (1, disconnect_message)] )
    else:
      self.debug_print_bad_message(message_id, pickled_payload)


  def unpickle(self, message_type, pickled_payload):
    """
    unpickle a payload according to the message type.
    """
    return unpicklers[message_type](self, pickled_payload)


  def unpickle_handshake_msg(self, pickled_payload):
    """
    Unpickle a pickled (serialized) payload.
    """
    (peer_id, peer_dict) = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'handshake_msg\' message.'),
#                        (2, 'peer_id = {}'.format([peer_id])),
#                        (3, 'peer_dict:'),
#                        (3, peer_dict)] )
    
    return (peer_id, peer_dict)


  def unpickle_sync_req(self, pickled_payload):
    """
    Unpickle a pickled (serialized) synch request.
    """
    store_id = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'sync_req\' message.'),
#                        (2, 'store_id = {}'.format([store_id]))] )
    
    return store_id

  def unpickle_merkel_tree_msg(self, pickled_payload):
    """
    Unpickle a pickled (serialized) Merkle tree.
    """
    merkel_tree = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'merkel_tree_msg\' message.'),
#                        (4, 'merkel_tree:')] )
#     
#     if self.debug_verbosity >= 4:
#       directory_merkel_tree.print_tree(merkel_tree)
    
    return merkel_tree
  
  def unpickle_update_file_msg(self, pickled_payload):
    """
    Unpickle a pickled (serialized) path and contents.
    """
    relative_path, file_contents = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'update_file_msg\' message.'),
#                        (2, 'relative_path = {}'+relative_path),
#                        (5, 'file_contents:'),
#                        (5, file_contents)] )
    
    return relative_path, file_contents
   
  def unpickle_delete_file_msg(self, pickled_payload):
    """
    Unpickle a pickled (serialized) path.
    """
    relative_path = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'delete_file_msg\' message.'),
#                        (2, 'relative_path = '+relative_path)] )
    
    return relative_path

  def unpickle_sync_complete_msg(self, pickled_payload):
    """
    Do nothing
    """
#     self.debug_print( (1, 'Unpickled a (empty) \'sync_complete_msg\' message.') )
    return
  
  def unpickle_verify_sync_req(self, pickled_payload):
    """
    Unpickle a pickled (serialized) nonce from a verify synch request 
    """
    nonce = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'verify_sync_req\' message.'),
#                        (3, 'nonce = {}'.format(nonce))] )
    
    return nonce


  def unpickle_verify_sync_resp(self, pickled_payload):
    """
    Unpickle a pickled (serialized) verification hash.
    """
    verification_hash = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'verify_sync_resp\' message.'),
#                        (3, 'verification_hash = {}'.format([verification_hash]))] )
    
    return verification_hash
  
  def unpickle_public_key_msg(self, pickled_payload):
    """
    Unpickle a pickled (serialized) public key.
    """
    public_key_file_contents = cPickle.loads(pickled_payload)
#     self.debug_print( [(1, 'Unpickled a \'public_key_msg\' message.'),
#                        (3, 'public_key_file_contents = {}'.format([public_key_file_contents]))] )
    
    return public_key_file_contents
  
  #################################
  # Debug and development methods #
  #################################
  
  # TODO: Generalize a subset of this functionality to support the future scenario where a central server would initiate such an association.
  def manually_associate(self, peer_id, ip_address, public_key_file):
    """
    Manually associate with a peer and prepare to be a backup for that peer's store.
    """
    
    if not os.path.isfile(self.get_peer_key_path(peer_id)):
      # Copy the public key and associate it to the specified peer.
      shutil.copyfile(public_key_file, self.get_peer_key_path(peer_id))
    
    # Get the key object for the public key and generate the corresponding store ID.
    public_key = self.get_peer_key(peer_id)
    # Calculate the store ID that corresponds to this public key.
    store_id = self.generate_store_id(public_key)

    if not os.path.isfile(self.get_store_key_path(store_id)):
      # Store another copy of the key assigned to its store ID.
      shutil.copyfile(public_key_file, self.get_store_key_path(store_id))
      
    # Create the store directory.
    if not os.path.isdir(self._get_store_path(store_id)):
      # Create the store directory.
      os.makedirs(self._get_store_path(store_id))
      
    # Create a copy of our `store_dict` for staging changes and insert the new metadata.
    if store_id in self.store_dict.keys():
      self.debug_print( (1, 'WARNING: Re-adding already known store.') )
      revision_data = self.store_dict[store_id].revision_data
      peers = self.store_dict[store_id].peers.union(set([peer_id, self.peer_id]))
    else:
      revision_data = INVALID_REVISION
      peers = set([peer_id, self.peer_id])
    
    store_data = StoreData(revision_data=revision_data, peers=peers)
    
    
    # Create a copy of our `store_dict` for staging changes and insert the new metadata.
    store_dict = copy.deepcopy(self.store_dict)
    store_dict[store_id] = store_data
    
    # Ensure the peer is associated with the store.
    if peer_id in self.peer_dict.keys():
      store_revisions = copy.deepcopy(self.peer_dict[peer_id].store_revisions)
    else:
      store_revisions = dict()
    
    if store_id not in store_revisions.keys():
      store_revisions[store_id] = None
      
    peer_data = PeerData(ip_address, store_revisions)
    
    # Create a copy of our `peer_dict` for staging changes and insert the new metadata.
    peer_dict = copy.deepcopy(self.peer_dict)
    peer_dict[peer_id] = peer_data
    
    # Ensure we are associated with the store.
    if store_id not in self.peer_dict[self.peer_id].store_revisions.keys():
      ip_address = self.peer_dict[self.peer_id].ip_address
      store_revisions = copy.deepcopy(self.peer_dict[self.peer_id].store_revisions)
      
      if store_id not in store_revisions.keys():
        store_revisions[store_id] = None
        
      peer_data = PeerData(ip_address, store_revisions)
      peer_dict[self.peer_id] = peer_data
    
    # Enact the changes.
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict, self.aes_key, self.aes_iv, self.merkel_tree)
    self.update_metadata(metadata)
    
    
  def debug_print(self, print_tuples):
    """
    Optionally print based on the object's verbosity setting and the required
    verbosity levels of the inputs. Taking input as a list of tuples allows 
    for multiple statements of differing verbosities to be dispatched from the 
    same call and be displayed under the same preamble and call stack (if any).
    
    Semantically, the levels are (currently) roughly:
    1: Interesting info for demoing.
    2: Additionally print uglies such as hashes and ID strings that are of nearly-intelligible length.
    3: Additionally print noisy stuff and larger data like peer and store dictionaries.
    4: "Oh shit, I have no idea where this bug is." (Call stack and Merkel trees.)
    5: Additionally print file contents.
    """
    # Handle the single tuple case.
    if isinstance(print_tuples, tuple):
      print_tuples = [print_tuples]
      
    # Nothing to print if this peer's debug verbosity setting doesn't meet any of the required levels.
    if all( (v > self.debug_verbosity) and (self.debug_verbosity<4) for v, _ in print_tuples):
      return
    
    if self.debug_preamble:
      print self.debug_preamble
    
    # Print call stack for sufficiently high verbosities.
    if self.debug_verbosity >= 4:
      print 'Call stack:'
      for frame in inspect.stack()[1:]:
        f_name = frame[3]
        print ' ', f_name
      print 'Debug message:'
    
    
    for verbosity, text in print_tuples:
      if self.debug_verbosity >= verbosity:       
        print text
        
    print


  def debug_print_bad_message(self, message_id, pickled_payload):
    """
    Print an unexpected (or bad) message to understand why the bad message came
    about.
    """
    self.debug_print( (1, 'Unexpected message received.'))
    
    # Lookup by value, an abuse of the dictionary type...
    # FIXME: Use `iteritems()` instead of `items()`
    message_type = [m_type for m_type, m_id in message_ids.items() if m_id == message_id][0]
    
    # Allow this message type's unpickler the opportunity to debug print a description of the message.
    self.unpickle(message_type, pickled_payload)


  #########
  # Tests #
  #########
  
  def test_client_ssl(self, peer_ip):
    """
    Test a client connection and send message across.
    """
    # FIXME: This modifies the metadata file, might not want such mangling
    self.record_peer_ip(-1, peer_ip)
    s = self.connect_to_peer(-1)
    print 'Peer Client: Connected to peer, transmitting important data twice.'
    s.write('I\'m still here')
    s.write('I\'m still here')
    s.close()
    
  def test_server_ssl(self):
    """
    Test a server connection, print received message both encrypted and
    decrypted, then close connection.
    """
    skt_listener = self.create_listening_socket()
    skt_raw, _ = skt_listener.accept()
    print 'Peer Server: A peer is attempting to connect'
    skt_ssl = ssl.wrap_socket(skt_raw, server_side=True, keyfile=self.private_key_file, certfile=self.x509_cert_file, ssl_version=ssl.PROTOCOL_SSLv3)
    decrypted = skt_ssl.recv(4096)
    encrypted = skt_raw.recv(4096) # Trashes the SSL communications, so do it second.
    print 'Peer Server: Data received from peer; displaying encrypted: ' + encrypted
    print 'Peer Server: Data received from peer; displaying decrypted: ' + decrypted
    skt_ssl.close()
    skt_raw.close()
    skt_listener.close()
    

  def test_client_handshake(self, peer_ip):
    """Test a connection between a peer and peer ip address."""
    # Back up the existing metadata.
    metadata_backup = self.metadata
    
    # Inject a new peer.
    test_peer_data = PeerData(ip_address=peer_ip, store_revisions={self.store_id: None})
    self.record_peer_data(-1, test_peer_data)
    
    skt_ssl = self.connect_to_peer(-1)
    try:
      self.peer_client_session(skt_ssl)
    except:
      skt_ssl.shutdown(socket.SHUT_RDWR)
      skt_ssl.close()
      # Restore metadata backup
      self.update_metadata(metadata_backup)
      raise
    
    skt_ssl.shutdown(socket.SHUT_RDWR)
    skt_ssl.close()
    # Restore metadata backup
    self.update_metadata(metadata_backup)

   
  def test_server_handshake(self):
    """Test a handshake for a peer listening for peers."""
    skt_listener = self.create_listening_socket()
    skt_listener.listen(1) # FIXME: Will need to deal with multiple peer clients eventually
    skt_raw, (peer_ip, _) = skt_listener.accept()
    skt_ssl = ssl.wrap_socket(skt_raw, server_side=True, keyfile=self.private_key_file, certfile=self.x509_cert_file, ssl_version=ssl.PROTOCOL_SSLv3)
    try:
      self.peer_server_session(skt_ssl, peer_ip)
    except:
      skt_ssl.shutdown(socket.SHUT_RDWR)
      skt_ssl.close()
      raise
    
    skt_ssl.shutdown(socket.SHUT_RDWR)
    skt_ssl.close()
    

def test_ssl():
  """
  test peer connection test between a peer and Server.
  """
  print 'Executing peer connection test.'
  client = Peer(debug_verbosity=1, debug_preamble='Peer Client:')
  server = Peer(debug_verbosity=1, debug_preamble='Peer Server:')
  
  t1 = threading.Thread(target=server.test_server_ssl, args=())
  t2 = threading.Thread(target=client.test_client_ssl, args=('localhost',))
  t1.start()
  t2.start()
  t2.join()
  t1.join()


def test_handshake():
  """
  Test a handshake between a peer and client.
  """
  print 'Executing peer handshake test.'
  client = Peer(debug_verbosity=5, debug_preamble='Peer Client:')
  server = Peer(debug_verbosity=5, debug_preamble='Peer Server:')
  
  t1 = threading.Thread(target=server.test_server_handshake, args=())
  t2 = threading.Thread(target=client.test_client_handshake, args=('localhost',))
  t1.start()
  t2.start()
  t2.join()
  t1.join()

#from peer import *
def demo_A():
  peer_a = Peer(debug_verbosity=5, debug_preamble='Peer A:')
  peer_a.run()

def demo_B():
  peer_b = Peer(debug_verbosity=5, debug_preamble='Peer B:')
  
  with open('a_metadata_file.pickle', 'r') as f:
    peer_a_id = cPickle.load(f).peer_id
    
  peer_b.manually_associate(peer_a_id, 'ec2-54-87-72-190.compute-1.amazonaws.com', 'a_public_key.pem')
  peer_b.run()

def demo_server():
  peer_server = Peer(debug_verbosity=2, debug_preamble='Server:')
  peer_server.update_ip_address()
  peer_server.check_store()
  peer_server.run_peer_server()
  
def demo_client():
  peer_client = Peer(debug_verbosity=2, debug_preamble='Client:')
  with open('a_metadata_file.pickle', 'r') as f:
    peer_a_id = cPickle.load(f).peer_id
    
  peer_client.manually_associate(peer_a_id, 'ec2-54-87-72-190.compute-1.amazonaws.com', 'a_public_key.pem')
  peer_client.update_ip_address()
  peer_client.check_store()
  peer_client.run_peer_client(3)

def initialize_peer_configuration():
  print 'Creating initial configuration for peer.'
  Peer()
  print 'Done.'

message_ids = {'handshake_msg'     : 0,
               'sync_req'          : 1,
               'merkel_tree_msg'   : 2, 
               'update_file_msg'   : 3,
               'delete_file_msg'   : 4,
               'sync_complete_msg' : 5,
               'verify_sync_req'   : 6,
               'verify_sync_resp'  : 7,
               'disconnect_req'    : 8,
               'public_key_msg'    : 9    # FIXME: Should be relying on the SSL socket to verify this information.
               }

unpicklers = {'handshake_msg'     : Peer.unpickle_handshake_msg,
              'sync_req'          : Peer.unpickle_sync_req,
              'merkel_tree_msg'   : Peer.unpickle_merkel_tree_msg,
              'update_file_msg'   : Peer.unpickle_update_file_msg,
              'delete_file_req'   : Peer.unpickle_delete_file_msg,
              'sync_complete_msg' : Peer.unpickle_sync_complete_msg,
              'verify_sync_req'   : Peer.unpickle_verify_sync_req, 
              'verify_sync_resp'  : Peer.unpickle_verify_sync_resp,
              'disconnect_req'    : Peer.unpickle_delete_file_msg,
              'public_key_msg'    : Peer.unpickle_public_key_msg
              }

def main():
  peer = Peer(debug_verbosity=10)
  peer.run()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Run a StrongBox peer.')
  parser.add_argument('-i', '--init', action='store_true', help='Just initialize peer configuration')
  parser.add_argument('-c', '--peer-client', action='store_true', help='Run in peer client mode only.')
  parser.add_argument('-s', '--peer-server', action='store_true', help='Run in peer server mode only.')

  args = parser.parse_args()
  
  if args.init:
    initialize_peer_configuration()
  elif args.peer_client:
    demo_client()
  elif args.peer_server:
    demo_server()
  else:
    main()
