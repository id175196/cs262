"""
The peer class is really a lot bigger than I was expecting.
"""
import socket
import ssl
import client_encryption
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
import mt # Here because we unpickle Merkel trees. I'm still not certain this import is actually necessary...

# Named tuples have (immutable) class-like semantics for accessing fields, but are straightforward to pickle/unpickle.
# The following types are for important data whose contents and format should be relatively stable at this point.
PeerData = namedtuple('PeerData', 'ip_address, store_revisions')
StoreData = namedtuple('StoreData', 'revision_data, peers')
Metadata = namedtuple('Metadata', 'peer_id, peer_dict, store_id, store_dict')

class Peer:
  
  #########################
  # Primary functionality #
  #########################
  
  # These are the goods, implemented at a higher level than the lower methods.

  def __init__(self,
               directory=os.getcwd(),
               debug_verbosity=0,
               debug_prefix=None):
    """Initialize a `Peer` object."""
    self.debug_verbosity = debug_verbosity
    self.debug_preamble = debug_prefix
    
    # Get the encryption object
    self.encryption = client_encryption.ClientEncryption(directory) # FIXME: On first run_peer_server, need `ClientEncryption` to initialize directory structure and sign revision 0.
    
    self.private_key_file = self.encryption.private_key_loc
    self.x509_cert_file = self.encryption.x509_cert_loc
    self.metadata_file = os.path.join(self.encryption.personal_path_full,'metadata_file.pickle')
    self.backup_metadata_file = self.metadata_file + '.bak'
    
    self.load_metadata_file()
    
    self.update_ip_address()

     
  def run_peer_server(self):
    skt_listener = self.create_listening_socket()
    skt_listener.listen(1) # FIXME: Will need to deal with multiple peer clients eventually
    skt_raw, (peer_ip, _) = skt_listener.accept()
    skt_ssl = ssl.wrap_socket(skt_raw, server_side=True, keyfile=self.private_key_file, certfile=self.x509_cert_file, ssl_version=ssl.PROTOCOL_SSLv3)
    try:
      self.peer_server_session(skt_ssl, peer_ip)
    except:
      skt_ssl.shutdown(socket.SHUT_RDWR)
      skt_ssl.close()
      

  def peer_server_session(self, skt_ssl, peer_ip):
    # Get the peer client's handshake request.
    pickled_payload = self.receive_expected_message(skt_ssl, 'handshake_req')
    (client_peer_id, client_peer_dict) = self.unpickle('handshake_req', pickled_payload)
    
    # FIXME: For known client peers, will want to verify the public key provided to the SSL.
    
    # The peer client's knowledge of itself is at least as up to date as ours, so attempt to get up to date.
    self.record_peer_data(client_peer_id, client_peer_dict[client_peer_id])
    
    # Parse useful gossip from the peer client's peer dictionary
    self.learn_metadata_gossip(client_peer_dict)
    
    # If the peer client is in/made it into our dictionary (i.e. we share a store with them), handshake back.
    if client_peer_id in self.peer_dict.keys():
      self.send_handshake_req(skt_ssl)
    # Otherwise, disconnect.
    else:
      self.send_disconnect_req(skt_ssl, 'No stores in common.')
      raise Exception() # TODO: At least provide a specific exception type to parse.

    # Get the peer client's sync request.
    pickled_payload = self.receive_expected_message(skt_ssl, 'sync_req')
    sync_store_id = self.unpickle('sync_req', pickled_payload)
    
    # Figure out what type of sync we'll be conducting.
    sync_type = self.determine_sync_type(client_peer_id, sync_store_id)
    
    

    # Session over, send the peer client a disconnect request.
    self.send_disconnect_req(skt_ssl, 'Session complete.')
  
      
  def peer_client_session(self, skt_ssl):
    # Initiate handshake with the peer server, providing pertinent metadata about ourselves and gossip.
    self.send_handshake_req(skt_ssl)
    
    # Get the server's response handshake.
    pickled_payload = self.receive_expected_message(skt_ssl, 'handshake_req')
    (server_peer_id, server_peer_dict) = self.unpickle('handshake_req', pickled_payload)
    
    # The peer server's knowledge of itself is at least as up to date as ours, so trust what it says.
    self.record_peer_data(server_peer_id, server_peer_dict[server_peer_id])
    
    # Parse useful gossip from the peer server's peer dictionary
    self.learn_metadata_gossip(server_peer_dict)

    # Select a store to sync with the peer server.
    store_id = self.select_sync_store(server_peer_id)
    
    # Quit the session if we couldn't find a store to sync.
    if not store_id:
      self.send_disconnect_req(skt_ssl, 'No stores to sync.')
      # FIXME: Raise a meaningful exception.
      raise Exception()
    
    # Initiate a sync.
    self.send_sync_req(skt_ssl, store_id)
    
    
    # Session over, get the peer server's disconnect request
    pickled_payload = self.receive_expected_message(skt_ssl, 'disconnect_req')
    disconnect_message = self.unpickle('disconnect_req', pickled_payload)
    self.debug_print( [(1, 'Peer requested disconnect reporting the following:'),
                       (1, disconnect_message)] )

  
  def do_sync(self, sync_type, store_id):
    if sync_type == 'receive':
      self.sync_receive(store_id)
      
  ####################
  # Class attributes #
  ####################
  
  message_ids = {'handshake_req'    : 0,
                 'sync_req'         : 1,
                 'merkel_tree_msg'  : 2, 
                 'update_file_req'  : 3, # FIXME
                 'delete_file_req'  : 4, # FIXME
                 'verify_sync_req'  : 5, # FIXME: Provide salt for Merkle tree, update peer's revision data upon verification 
                 'verify_sync_resp' : 6, # FIXME
                 'disconnect_req'   : 7 # FIXME
                 }
  
  unpicklers = {'handshake_req'    : Peer.unpickle_handshake_req,
                'sync_req'         : Peer.unpickle_sync_req,
                'merkel_tree_msg'  : Peer.unpickle_merkel_tree_msg,
                'update_file_req'  : 3, # FIXME
                'delete_file_req'  : 4, # FIXME
                'verify_sync_req'  : 5, # FIXME: Provide salt for Merkle tree, update peer's revision data upon verification 
                'verify_sync_resp' : 6, # FIXME
                'disconnect_req'   : 7 # FIXME
                }
  
  
  # FIXME: Beware the unsafety if accessing mutable fields from multiple threads.
  listening_port = 51337 # TODO: Magic number. Ideally would want listening listening_port number to be configurable per peer.
  
  
  ##########################
  # Initialization methods #
  ##########################
  
  def generate_peer_id(self):
    """
    Generate a quasi-unique ID for this peer using a hash (SHA-256, which
    currently has no known collisions) of the owner's public key "salted" with a
    random number.
    """
    peer_unique_string = self.encryption.import_public_key().exportKey() + str(random.SystemRandom().random())
    peer_id = hashlib.sha256(peer_unique_string).digest()
    self.debug_print( (2, 'Generated new peer ID: ' + peer_id) )
    return peer_id
    

  def generate_store_id(self, public_key=None):
    """
    Store IDs are meant to uniquely identify a store/user. They are essentially
    the RSA public key, but we use use their SHA-256 hash to "flatten" them to
    a shorter, predictable length.
    """
    # Default to using own public key.
    if not public_key:
      public_key = self.encryption.import_public_key()
      
    store_id = hashlib.sha256(public_key.exportKey()).digest()
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
        metadata = self.generate_initial_metadata()
        # Immediately write out to non-volatile storage since `update_metadata()` expects a pre-existing file to be made the backup.
        with open(self.metadata_file, 'w') as f:
          cPickle.dump(metadata, f)
    finally:  
      # Bring the new values into effect
      self._metadata = Metadata(None, None, None, None) # Create a null object to update against.
      self.update_metadata(metadata)


  def generate_initial_metadata(self):
    """
    Generate a peer's important metadata the first time it is instantiated.
    """
    peer_id = self.generate_peer_id()
    store_id = self.generate_store_id()
    ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin'] # FIXME: Would like to sign this
    
    # FIXME: Idempotently initialize/ensure personal directory structure here including initial revision number.
    revision_data = self.encryption.get_signed_revision()
    peer_dict = {peer_id: PeerData(ip_address, {store_id: revision_data})}
    store_dict = {store_id: StoreData(revision_data, set([peer_id]))}
    
    # Load the initial values into a `Metadata` object.
    metadata = Metadata(peer_id, peer_dict, store_id, store_dict)
    return metadata
    
  
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
    
    
#   # FIXME: Untested
#   def record_store_association(self, peer_id, store_id):
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
      if (any(self.gt_revision_data(g_rev, r_rev) for g_rev, r_rev in zip(gossip_revisions, recorded_revisions))):
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
    
    
  ##################################
  # Encryption object interactions #
  ##################################
  
  def record_peer_pubkey(self, peer_id, peer_pubkey):
    """
    Used to record a peer's public key upon first encounter. The key is 
    subsequently used to verify SSL connections and signatures.
    """
    # Public key should be passed as text, so write out directly to the appropriate file.
    self.encryption.write_pubkey(peer_id, peer_pubkey)


  def record_store_pubkey(self, peer_id, peer_pubkey):
    """
    Used to record a store's public key upon association. The key is 
    subsequently used for signature verification.
    """
    # NOTE: This is identical to the above function for peers, but affords the flexibility to quickly change the implementation later.
    # Public key should be passed as text, so write out directly to the appropriate file.
    self.encryption.write_pubkey(peer_id, peer_pubkey)

    
  def gt_revision_data(self, store_id, revision_data_1, revision_data_2):
    """
    Returns `True` if `revision_data_1` passes signature verification and either 
    is later than `revision_data_2` or that revision fails signature verification.
    """
    # `revision_data_1` is `None` or its signature doesn't verify.
    if (not revision_data_1) or (not self.verify_rev_number(store_id, revision_data_1)):
      return False
    
    # `revision_data_2` is `None` or its signature doesn't verify.
    if (not revision_data_2) or (not self.verify_rev_number(store_id, revision_data_2)):
      return True
    
    # FIXME: Figure out proper way to extract revision numbers.
    if revision_data_1.revision_number > revision_data_2.revision_number:
      return True
    else:
      return False

  
  def verify_rev_number(self, store_id, revision_data):
    """
    Verify the signature of a received revision number.
    """
    # FIXME: Implement.
    return True
  
  
  def get_merkel_tree(self, store_id):
    """Get the locally computed Merkel tree for a store."""
    # Own store
    if store_id == self.store_id:
      return self.encryption.get_personal_mt()
    # Peer's store
    else:
      return self.encryption.get_foreign_mt(store_id)
    

  def diff_store_to_merkel_tree(self, store_id, mt_old):
    """
    Compute the difference between the current contents of the specified store 
    and those indicated by the older, provided Merkel tree.
    """
    mt_new = self.encryption.get_foreign_mt(store_id)
    
    updated_files, deleted_files = mt.mt_file_diffs(mt_new, mt_old)
    return updated_files, deleted_files
    
  #########################
  # Communication helpers #
  #########################
  
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
  
  
  def select_sync_store(self, peer_id):
    """
    Select which of a peer server's stores to sync with.
    """
    # Get the communicating peer server's list of stores and respective revision data.
    peer_store_revisions = self.peer_dict[peer_id].store_revisions
    
    # Only interested in stores the peer also has.
    mutual_stores = set(peer_store_revisions.keys())
    
    potential_stores = set()
    
    # Consider stores which the peer server has a later revision for.
    for store_id in mutual_stores:
      if self.gt_revision_data(peer_store_revisions[store_id], self.store_dict[store_id].revision_data):
        potential_stores.add(store_id)
        
    # If the peer server doesn't have any updates for us, consider updates we have for them.
    if not potential_stores:
      for store_id in mutual_stores:
        if self.gt_revision_data(self.store_dict[store_id].revision_data, peer_store_revisions[store_id]):
          potential_stores.add(store_id)
    
    # If we are both at the same revision for all mutual stores, we will verify one another's revision for some mutual store.
    if not potential_stores:
      # Only consider the mutual stores for which both ends have a valid revision.
      for store_id in mutual_stores:
        if self.store_dict[store_id].revision_data and peer_store_revisions[store_id]:
          potential_stores.add(store_id)
          
    # Return `None` if we couldn't find a store to sync.
    if not potential_stores:
      return None
    # Otherwise, choose a random store from the determined options.
    return random.sample(potential_stores, 1)[0]
  
  
  def determine_sync_type(self, peer_id, store_id):
    """
    Figure out what type of synchronization (send, receive, or check) we'll be 
    participating in.
    """
    # Get the communicating peer server's list of stores and respective revision data.
    our_revision = self.store_dict[store_id].revision_data
    peer_revision = self.peer_dict[peer_id].store_revisions[store_id]
    
    # Communicating peer has a newer revision of the store than us.
    if self.gt_revision_data(peer_revision, our_revision):
      return 'receive'
    
    # We have a newer revision of the store than the communicating peer.
    if self.gt_revision_data(our_revision, peer_revision):
      return 'send'
    
    # If neither the communicating peer nor we have a valid revision for the store, raise an exception.
    if (not our_revision) and (not peer_revision):
      # FIXME: Raise a meaningful exception.
      raise Exception()
    
    # Otherwise, we both have the same (valid) revision.
    return 'check'
  
  
  def sync_receive(self, skt, store_id):
    """Conduct a sync as the receiving party."""
    # Submit our Merkel tree for the store so the communicating peer can identify which files require modification.
    self.send_merkel_tree_msg(skt, store_id)
    
  def sync_send(self, skt, store_id):
    """Conduct a sync as the sending party."""
    # Receive the communicating peer's Merkel tree for the store.
    pickled_payload = self.receive_expected_message(skt, 'merkel_tree_msg')
    merkel_tree = self.unpickle('merkel_tree_msg', pickled_payload)
    
    updated_files, deleted_files = self.diff_store_to_merkel_tree(store_id, merkel_tree)
    
  #####################
  # Messaging methods #
  #####################
  
  def send(self, skt, message_id, message_data):
    pickled_payload = cPickle.dumps(message_data)
    message_body = (message_id, pickled_payload)
    pickled_message = cPickle.dumps(message_body)
    skt.send(struct.pack('!I', len(pickled_message))+pickled_message)
    
  def send_handshake_req(self, skt):
    message_id = self.message_ids['handshake_req']
    message_data = (self.peer_id, self.peer_dict)
    self.send(skt, message_id, message_data)
    
  def send_sync_req(self, skt, store_id):
    message_id = self.message_ids['sync_req']
    message_data = store_id
    self.send(skt, message_id, message_data)
    
  def send_merkel_tree_msg(self, skt, store_id):
    message_id = self.message_ids['merkel_tree_msg']
    message_data = self.get_merkel_tree(store_id)
    self.send(skt, message_id, message_data)
        
  def send_disconnect_req(self, skt, disconnect_message):
    message_id = self.message_ids['disconnect_req']
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
      
      # Message has incorrect length.
      if len(message_buffer) != (length + 4):
        # FIXME: Provide a meaningful exception.
        raise Exception()
      
      # Unpickle the message contents
      pickled_message = message_buffer[4:4+length]
      (message_id, pickled_payload) = cPickle.loads(pickled_message)
      return message_id, pickled_payload
  
  
  def receive_expected_message(self, skt, expected_message_type):
    """
    Receive a message, automatically handling situations where the message was 
    not of the type expected.
    """
    expected_message_id = self.message_ids[expected_message_type]
    
    message_id, pickled_payload = self.receive(skt)
    if message_id != expected_message_id:
      self.handle_unexpected_message(message_id, pickled_payload)
      # FIXME: Use a more specific exception.
      raise Exception()
    return pickled_payload
    
    
  def handle_unexpected_message(self, message_id, pickled_payload):
    if message_id == self.message_ids['disconnect_req']:
      # Unpickle message data from `'disconnect_req'` message type.
      disconnect_message = self.unpickle('disconnect_req', pickled_payload)
      self.debug_print( [(1, 'Peer requested disconnect, reporting the following:'),
                         (1, disconnect_message)] )
    else:
      self.debug_print_bad_message(message_id, pickled_payload)


  def unpickle(self, message_type, pickled_payload):
    return self.unpicklers[message_type](self, pickled_payload)
  
      
  def unpickle_handshake_req(self, pickled_payload):
    (peer_id, peer_dict) = cPickle.loads(pickled_payload)
    self.debug_print( [(1, 'Unpickled a \'handshake_req\' message.'),
                       (2, 'peer_id = '+peer_id),
                       (2, 'peer_dict:'),
                       (2, peer_dict)] )
    
    return (peer_id, peer_dict)


  def unpickle_sync_req(self, pickled_payload):
    store_id = cPickle.loads(pickled_payload)
    self.debug_print( [(1, 'Unpickled a \'sync_req\' message.'),
                       (2, 'store_id = '+store_id)] )
    
    return store_id

  def unpickle_merkel_tree_msg(self, pickled_payload):
    merkel_tree = cPickle.loads(pickled_payload)
    self.debug_print( [(1, 'Unpickled a \'merkel_tree_msg\' message.'),
                       (4, 'merkel_tree:'+merkel_tree)] )
    
    if self.debug_verbosity >= 4:
      merkel_tree.PrintHashList() # If this doesn't work due to unpickling, could also try `MarkleTree.PrintHashList(merkel_tree)`
    
    return merkel_tree


  #################################
  # Debug and development methods #
  #################################
  
  # TODO: Generalize a subset of this functionality to support the future scenario where a central server would initiate such an association.
  def manually_associate(self, peer_id, ip_address, public_key_file):
    """
    Manually associate with a peer and prepare to be a backup for that peer's store.
    """
    # Idempotency. Also, might've already learned about this peer through gossip about a mutual store. 
    if peer_id not in self.peer_dict.keys():
      # Copy the public key and associate it to the specified peer.
      shutil.copyfile(public_key_file, self.encryption.public_foreign_key_loc(peer_id))
    
    # Get the key object for the public key and generate the corresponding store ID
    public_key = self.encryption.import_public_key(peer_id)
    # Calculate the store ID that corresponds to this public key.
    store_id = self.generate_store_id(public_key)

    # Idempotency.
    if store_id not in self.store_dict.keys():
      # Store another copy of the key assigned to its store ID.
      shutil.copyfile(public_key_file, self.encryption.public_foreign_key_loc(store_id))
      
      # Initialize the directory structure to back up this store.
      # FIXME: Need to thoroughly examine the effects of setting the `validation_tup` argument to `None`.
      self.encryption.init_remote(store_id, None)
      
      # Create a copy of our `store_dict` for staging changes and insert the new metadata.
      store_dict = copy.deepcopy(self.store_dict)
      store_data = StoreData(revision_data=None, peers=set([peer_id]))
      store_dict[store_id] = store_data
      
      # Prepare the corresponding changes to our `peer_dict`
      if peer_id in self.peer_dict.keys():
        store_revisions = self.peer_dict[peer_id].store_revisions
      else:
        store_revisions = dict()
      store_revisions[store_id] = None
      peer_data = PeerData(ip_address, store_revisions)
      
      # Create a copy of our `peer_dict` for staging changes and insert the new metadata.
      peer_dict = copy.deepcopy(self.peer_dict)
      peer_dict[peer_id] = peer_data
      
      # Enact the changes.
      metadata = Metadata(self.peer_id, peer_dict, self.store_id, store_dict)
      self.update_metadata(metadata)
    
    
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
    self.debug_print( (1, 'Unexpected message received.'))
    
    # Lookup by value, an abuse of the dictionary type...
    message_type = [m_type for m_type, m_id in self.message_ids.items() if m_id == message_id][0]
    
    # Allow this message type's unpickler the opportunity to debug print a description of the message.
    self.unpickle(message_type, pickled_payload)


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



def main():
  test_handshake()


if __name__ == '__main__':
  main()
