"""
The peer class is really a lot bigger than I was expecting.
"""
import socket
import ssl
import client_encryption
import os
import cPickle # Supposed to be orders of magnitude faster than `pickle`, but with some limitations on serializing new classes.
import hashlib
import random
import shutil
import struct
import inspect
import json
import copy
from urllib2 import urlopen
from collections import namedtuple

# Named tuples have (immutable) class-like semantics for accessing fields, but are straightforward to pickle/unpickle.
# The following types are for important data whose contents and format should be relatively stable at this point.
PeerData = namedtuple('PeerData', 'ip_address, store_revisions')
StoreData = namedtuple('StoreData', 'revision_data, peers')
Metadata = namedtuple('Metadata', 'peer_id, peer_dict, store_id, store_dict')

class Peer:
  
  #################
  # Object fields #
  #################
  
  # FIXME: Beware the unsafety if accessing fields from multiple threads.
  listening_port = 51337 # TODO: Magic number. Ideally would want listening listening_port number to be configurable per peer.
  
  
  ##########################
  # Initialization methods #
  ##########################
  
  def generate_peer_id(self):
    """
    Generate a quasi-unique ID for this peer using a hash (SHA-256, which
    currently has no known collisions) of the user's public key "salted with a
    random number.
    """
    peer_unique_string = self.encryption.import_public_key().exportKey() + str(random.SystemRandom().random())
    peer_id = hashlib.sha256(peer_unique_string).digest()
    self.debug_print( (2, 'Generated new peer ID: ' + peer_id) )
    return peer_id
    

  def generate_store_id(self):
    """
    Store IDs are meant to uniquely identify a store/user. They are essentially
    the RSA public key, but we use use their SHA-256 hash to "flatten" them to
    a shorter, predictable length.
    """
    store_id = hashlib.sha256(self.encryption.import_public_key().exportKey()).digest()
    self.debug_print( (2, 'Generated new store ID: ' + store_id) )
    return store_id
  
  # TODO: De-uglify
  # FIXME: PyDoc
  # Use a file to permanently store certain metadata.
  def load_metadata_file(self):
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
        # Prepare initial values.
        peer_id = self.generate_peer_id()
        store_id = self.generate_store_id()
        ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin'] # FIXME: Would like to sign this
        revision_data = self.get_rev_data(store_id)
        peer_dict = {peer_id: PeerData(ip_address, {store_id: revision_data})}
        store_dict = {store_id: StoreData(revision_data, set([peer_id]))}
        
        # Load the initial values into a `Metadata` object.
        metadata = Metadata(peer_id, peer_dict, store_id, store_dict)
        # Immediately write out to non-volatile storage.
        with open(self.metadata_file, 'w') as f:
          cPickle.dump(metadata, f)
    finally:  
      # Bring the new values into effect
      self._metadata = Metadata(None, None, None, None) # Create a null object to update against.
      self.update_metadata(metadata)

  
  
  def __init__(self, directory=os.getcwd(), debug_verbosity=0, debug_prefix=None):
    self.debug_verbosity = debug_verbosity
    self.debug_preamble = debug_prefix
    
    # Get the encryption object
    self.encryption = client_encryption.ClientEncryption(directory) # FIXME: On first run, need `ClientEncryption` to initialize directory structure and sign revision 0.
    
    self.private_key_file = self.encryption.private_key_loc
    self.x509_cert_file = self.encryption.x509_cert_loc
    self.metadata_file = os.path.join(self.encryption.personal_path_full,'metadata_file.pickle')
    self.backup_metadata_file = self.metadata_file + '.bak'
    
    self.load_metadata_file()
    
    self.update_ip_address()

  ####################
  # Metadata methods #
  ####################
  
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
  
  # FIXME: This is returning `None` even though `self._metadata` gives the correct output.
  @property
  def metadata(self):
    """
    Important metadata about peers and stores. Access is controlled to ensure 
    that all changes are backed up to primary storage.
    """
    return self._metadata
  
  def update_metadata(self, metadata):
    """
    All updates to a peer's stored metadata occur through this function so
    we can ensure that changes are backed up to primary storage before coming 
    into effect.
    """
    # Only update if necessary.
    if metadata == self.metadata:
      self.debug_print( (2, 'No new metadata; update skipped.') )
      return
    
    # Copy the previous metadata file to the backup location.
    shutil.copyfile(self.metadata_file, self.backup_metadata_file)
    
    # Write the new metadata to primary storage.
    with open(self.metadata_file, 'w') as f:
      cPickle.dump(metadata, f)
    
    # Refer to the new metadata now that it's been stored to disk
    self._metadata = metadata
    
    self.debug_print( [(1, 'Updated metadata.'),
                       (2, 'peer_id = {}'.format(self.peer_id)),
                       (2, 'peer_dict = {}'.format(self.peer_dict)),
                       (2, 'store_id = {}'.format(self.store_id)),
                       (2, 'store_dict = {}'.format(self.store_dict))] )

        
  def record_store_association(self, peer_id, store_id):
    """
    Permanently record the list of stores that other peers are associated
    with. Also, if the connecting peer is a backup for a store that this peer is
    also a backup for, update that store's metadata accordingly.
    """
    # Do nothing if this peer's associations were already known
    if (store_id in self.store_dict.keys()) and \
        (peer_id in self.store_dict[store_id].peers) and \
        (store_id in self.peer_dict[peer_id].stores):
      return
    
    self.debug_print( [(1, 'Recording new store association.'), 
                       (2, 'peer_id = ' + peer_id + ', store_id=' + store_id)])
    
    # Create a copy of the peer metadata to stage the new changes.
    peer_dict = self.peer_dict.copy()
    peer_dict[peer_id].stores.add(store_id)
    
    # Create a copy of the store metadata to stage the new changes.
    store_dict = self.store_dict.copy()
    
    # Creating a new store
    if store_id not in self.store_dict.keys():
      store_data = StoreData(0, set()) # FIXME: Will need actual revision number format rather than `0`.
    # The previously known store only needs to be amended.
    else:
      store_data = copy.deepcopy(self.store_dict[store_id]) # Named tuples (and tuples in general) require deep copying... I think.
    store_data.peers.add(peer_id)
    # FIXME: Will also want to record this peer's revision number.
    store_dict[store_id] = store_data
    
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict)
    self.update_metadata(metadata)

  def record_peer_data(self, peer_id, peer_data):
    """
    Update the recorded metadata for an individual peer.
    """
    peer_mutual_stores = set(peer_data.store_revisions.keys()).intersection(set(self.store_dict.keys()))
    # Only want to track peers that are associated with a store we're concerned with.
    if not peer_mutual_stores:
      return
    # Only update the metadata if necessary
    if (peer_id in self.peer_dict.keys()) and \
        (peer_data.ip_address == self.peer_dict[peer_id].ip_address) and \
        (peer_data.store_revisions == self.peer_dict[peer_id].store_revisions):
      return
    # Peers don't initially know their own IP addresses, so also throw out invalid changes to the IP address.
    elif (peer_id in self.peer_dict.keys()) and \
        (not peer_data.ip_address) and \
        (peer_data.store_revisions == self.peer_dict[peer_id].store_revisions):
      # FIXME: This edge case should be fixed now, verify
      self.debug_print( [(0, '!!!! Received report of null IP address !!!!'),
                         (0, 'peer_id = '+peer_id),
                         (0, 'peer_data:')
                         (0, peer_data)] )
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
      
    # Record the peer's associations with only the stores we are already associated with.
    for s_id in peer_mutual_stores:
      store_revisions[s_id] = peer_data.store_revisions[s_id]
      # Simultaneously ensure the store's association with the peer to maintain the bidirectional mapping.
      store_dict[s_id].peers.add(peer_id) 
    
    # FIXME
    # Again, peers are unaware of their own IP addresses, so only take valid changes thereof
    if peer_data.ip_address:
      ip_address = peer_data.ip_address
    
    # Enact the update.
    peer_dict[peer_id] = PeerData(ip_address, store_revisions)
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict)
    self.update_metadata(metadata)
  
  def learn_metadata_gossip(self, peer_dict):
    """
    Update this peer's metadata based on gossip received from another peer.
    """
    # Update our metadata on mutual peers as needed.
    mutual_peers = set(peer_dict.keys()).intersection(set(self.peer_dict.keys()))
    for peer_id in mutual_peers:
      # Only update if the received metadata is newer. This is indicated by the
      #  gossip showing a peer to know a newer revision of (an associated) store 
      #  than we knew that it knew about (...such a convoluted description. FIXME).
      
      # Stores that both we and the gossip know a peer to be associated with
      peer_mutual_stores = set(peer_dict[peer_id].store_revisions.keys()).intersection(set(self.peer_dict[peer_id].store_revisions.keys()))
      
      gossip_revisions = [peer_dict[peer_id].store_revisions[s_id] for s_id in peer_mutual_stores]
      recorded_revisions = [self.peer_dict[peer_id].store_revisions[s_id] for s_id in peer_mutual_stores]
      # Compare what the gossip says this peer knows against what we've recorded
      if (any(self.gt_revision_number(g_rev, r_rev) for g_rev, r_rev in zip(gossip_revisions, recorded_revisions))):
        # The gossip indicates more recent knowledge of the peer in question than we have
        self.record_peer_data(peer_id, peer_dict[peer_id])
    
    # Learn new peers associated with our stores of interest.
    unknown_peers = set(peer_dict.keys()).difference(set(self.peer_dict.keys()))
    for peer_id in unknown_peers:
      if set(peer_dict[peer_id].store_revisions.keys()).intersection(set(self.peer_dict.keys())):
        self.record_peer_data(peer_id, peer_dict[peer_id])
    
  def update_ip_address(self):
    """Update this peer's already existing IP address data."""
    # Create staging copy of data to be changed
    peer_dict = copy.deepcopy(self.peer_dict)
    
    ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin'] # FIXME: Would like to sign this
    peer_data = PeerData(ip_address, peer_dict[self.peer_id].store_revisions)
    peer_dict[self.peer_id] = peer_data
    metadata = Metadata(self.peer_id, peer_dict, self.store_id, self.store_dict)
    self.update_metadata(metadata)
    
  #################################
  # Encryption class interactions #
  #################################
  
  # Associate a store to a peer
  def associate_store(self, peer_id, store_id):
    """
    Associate a store this peer has been requested to back up with some other
    peer that it is communicating with (initializing the directory structure for
    a new store, if necessary.
    """
    if store_id not in self.store_dict.keys():
      # Initialize the directory structure to back up this store
      # FIXME: DO ACTUAL WORK HERE
      self.debug_print( (1, 'Creating storage for new store.') )
      None
    # Ensure this store association is recorded
    self.record_store_association(peer_id, store_id)
    
  def record_peer_key(self, peer_pubkey):
    # FIXME: DO THE WORK. Also, will want to store these independently of the store directories so we can easily check the public key of 
    None

  def get_rev_data(self, store_id):
    """
    Determine what revision of the specified store we have.
    """
    
    #FIXME: Implement
    None
    
  def gt_revision_number(self, revision_a, revision_b):
    """
    Returns `True` if both revisions verify and revision A is numbered higher
    than B.
    """
    # FIXME
    return True
    
  def verify_rev_number(self, store_id):
    """
    Verify the signature of a received revision number.
    """
    
    # FIXME: Implement. Also, how do we know who the store's owner is? Will need to set that during store creation.
    None
    
  ########################
  # Steady-state methods #
  ########################
  

  def connect_to_peer(self, peer_id):
    # TODO: Raises `KeyError` exception on invalid UUID.
    peer_ip = self.peer_dict[peer_id].ip_address
    # FIXME: Want to verify peer server's public key
    skt = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_SSLv3)
    skt.connect((peer_ip, self.listening_port))
    return skt
  
  def create_listening_socket(self):
    skt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    skt.bind(('', self.listening_port))
    return skt
  
  
  def peer_client_session(self, skt_ssl):
    # Identify yourself to the peer server.
    self.send_handshake_req(skt_ssl)
    
    # Get the server's response handshake.
    message_id, pickled_payload = self.receive(skt_ssl)
    if message_id != message_ids['handshake_req']:
      self.handle_unexpected_message(message_id, pickled_payload)
      raise Exception()
    # Unpickle message data from `'handshake_req'` message type.
    (peer_id, peer_dict) = unpickle(pickled_payload)
    self.debug_print( [(1, 'Received handshake from peer server.'),
                       (2, 'peer_id = '+peer_id),
                       (2, 'peer_dict:'),
                       (2, peer_dict)] )
    
    # The peer server's knowledge of itself is at least as up to date as ours, so attempt to get up to date.
    self.record_peer_data(peer_id, peer_dict[peer_id])
    
    # Parse useful gossip from the peer server's peer dictionary
    self.learn_metadata_gossip(peer_dict)
    
    message_id, pickled_payload = self.receive(skt_ssl)
    self.handle_unexpected_message(message_id, pickled_payload)

  
  def peer_server_session(self, skt_ssl, peer_ip):
    # Get the peer client's handshake request.
    (message_id, pickled_payload) = self.receive(skt_ssl)
    if message_id != message_ids['handshake_req']:
      self.handle_unexpected_message(message_id, pickled_payload)
      raise Exception()
    # Unpickle message data from `'handshake_req'` message type.
    (peer_id, peer_dict) = unpickle(pickled_payload)
    self.debug_print( [(1, 'Received handshake from peer client.'),
                       (2, 'peer_id = '+peer_id),
                       (2, 'peer_dict:'),
                       (2, peer_dict)] )
    
    # FIXME: For known client peers, will want to verify the public key provided to the SSL.
    
    # The peer client's knowledge of itself is at least as up to date as ours, so attempt to get up to date.
    self.record_peer_data(peer_id, peer_dict[peer_id])
    
    # Parse useful gossip from the peer client's peer dictionary
    self.learn_metadata_gossip(peer_dict)
    
    # If the peer client is in our dictionary (i.e. we share a store with them), handshake back.
    if peer_id in self.peer_dict.keys():
      self.send_handshake_req(skt_ssl)
    # Otherwise, disconnect.
    else:
      self.send_disconnect_req(skt_ssl, 'No stores in common.')
      raise Exception() # TODO: At least provide a specific exception type to parse.
          
    self.send_disconnect_req(skt_ssl, 'Session complete.')
      
  def run(self):
    skt_listener = self.create_listening_socket()
    skt_listener.listen(1) # FIXME: Will need to deal with multiple peer clients eventually
    skt_raw, (peer_ip, _) = skt_listener.accept()
    skt_ssl = ssl.wrap_socket(skt_raw, server_side=True, keyfile=self.private_key_file, certfile=self.x509_cert_file, ssl_version=ssl.PROTOCOL_SSLv3)
    try:
      self.peer_server_session(skt_ssl, peer_ip)
    except:
      skt_ssl.shutdown(socket.SHUT_RDWR)
      skt_ssl.close()

  #####################
  # Messaging methods #
  #####################
  
  def send(self, skt, message_id, message_data):
    pickled_payload = cPickle.dumps(message_data)
    message_body = (message_id, pickled_payload)
    pickled_message = cPickle.dumps(message_body)
    skt.send(struct.pack('!I', len(pickled_message))+pickled_message)
    
  
  def send_handshake_req(self, skt):
    message_id = message_ids['handshake_req']
    message_data = (self.peer_id, self.peer_dict)
    self.send(skt, message_id, message_data)
    
  def send_identity_ack(self, skt):
    message_id = message_ids['identity_ack']
    message_data = None
    self.send(skt, message_id, message_data)
      
  def send_assoc_req(self, skt):
    message_id = message_ids['assoc_req']
    message_data = (self.peer_id, self.store_id)
    self.send(skt, message_id, message_data)
      
  def send_assoc_ack(self, skt):
    message_id = message_ids['assoc_ack']
    message_data = self.encryption.import_public_key().exportKey() # Own public key in string format
    self.send(skt, message_id, message_data)
    
  def send_disconnect_req(self, skt, disconnect_message):
    message_id = message_ids['disconnect_req']
    message_data = disconnect_message
    self.send(skt, message_id, message_data)    
      
  def receive(self, skt):
    message_buffer = skt.recv(4096)
    length_received = len(message_buffer)
    
    if length_received >= 4:
      length = struct.unpack('!I',message_buffer[0:4])[0]
      
      # Get the rest of the message if incomplete
      # FIXME: This helps, but doesn't guarantee a complete message
      if length_received < (length + 4):
        message_buffer += skt.recv((length + 4) - length_received)
      
      # Unpickle the message contents
      pickled_message = message_buffer[4:4+length]
      (message_id, pickled_payload) = cPickle.loads(pickled_message)
      return message_id, pickled_payload
    
  def handle_unexpected_message(self, message_id, pickled_payload):
    if message_id == message_ids['disconnect_req']:
      # Unpickle message data from `'disconnect_req'` message type.
      disconnect_message = unpickle(pickled_payload)
      self.debug_print( [(1, 'Peer requested disconnect, reporting the following:'),
                         (1, disconnect_message)] )
    else:
      self.debug_print_bad_message(message_id, pickled_payload)

  #################################
  # Debug and development methods #
  #################################
  
  def debug_print(self, print_tuples):
    """
    Optionally print based on the object's verbosity setting and the required
    verbosity levels of the inputs. Taking input as a list of tuples allows 
    for multiple statements of differing verbosities to be dispatched from the 
    same call and be displayed under the same preamble and call stack (if any).
    
    Semantically, the levels are (currently) roughly:
    1: Interesting info for the demo.
    2: Additionally watch the metadata changes and print uglies like ID strings.
    3: "Oh shit, I have no idea where this bug is."
    """
    # Handle the single tuple case.
    if isinstance(print_tuples, tuple):
      print_tuples = [print_tuples]
      
    # Nothing to print if this peer's debug verbosity setting doesn't meet any of the required levels.
    if all( (v > self.debug_verbosity) and (v<=2) for v, _ in print_tuples):
      return
    
    print self.debug_preamble
    
    # Print call stack for sufficiently high verbosities.
    if self.debug_verbosity > 2:
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
    self.debug_print( [(1, 'Unexpected message received. All sessions must begin with the peer client sending a handshake request.'),
                       (2, 'message_id = {}'.format(message_id)),
                       (2, 'Unpickled payload:'),
                       (2, unpickle(pickled_payload))] )
    
  #########
  # Tests #
  #########
  
  def test_client_ssl(self, peer_ip):
    # FIXME: This modifies the metadata file, might not want such mangling
    self.record_peer_ip(-1, peer_ip)
    s = self.connect_to_peer(-1)
    print 'Peer Client: Connected to peer, transmitting important data twice.'
    s.write('oh hai')
    s.write('oh hai')
    s.close()
    
  def test_server_ssl(self):
    skt_listener = self.create_listening_socket()
    skt_listener.listen(1)
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
  print 'Executing peer connection test.'
  import threading
  client = Peer(debug_verbosity=1, debug_prefix='Peer Client:')
  server = Peer(debug_verbosity=1, debug_prefix='Peer Server:')
  
  t1 = threading.Thread(target=server.test_server_ssl, args=())
  t2 = threading.Thread(target=client.test_client_ssl, args=('localhost',))
  t1.start()
  t2.start()
  t2.join()
  t1.join()

def test_handshake():
  print 'Executing peer handshake test.'
  import threading
  client = Peer(debug_verbosity=1, debug_prefix='Peer Client:')
  server = Peer(debug_verbosity=1, debug_prefix='Peer Server:')
  
  t1 = threading.Thread(target=server.test_server_handshake, args=())
  t2 = threading.Thread(target=client.test_client_handshake, args=('localhost',))
  t1.start()
  t2.start()
  t2.join()
  t1.join()

def unpickle(pickled_payload):
  return cPickle.loads(pickled_payload)

message_ids = {'handshake_req': 0,
               'sync_req': 1, # FIXME
               'sync_resp': 2, # FIXME
               'update_file_req': 3, # FIXME
               'delete_file_req': 4, # FIXME
               'verify_sync_req': 5, # FIXME: Provide salt for Merkle tree, update peer's revision data upon verification 
               'verify_sync_resp': 6, # FIXME
               'disconnect_req': 7 # FIXME
               }

# unpicklers = {'handshake_req': unpickle_handshake_req,
#               #'identity_ack': Has no data to unpickle
#               'assoc_req': unpickle_assoc_req,
#               'assoc_ack': unpickle_assoc_ack
#               }


    
def main():
  test_handshake()

if __name__ == '__main__':
  main()
