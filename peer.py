import socket
import ssl
import client_encryption
import os
import cPickle # Supposed to be orders of magnitude faster than `pickle` with some limitations on serializing new classes

class Peer:
  # List this object's fields (what's the Pythonic way?)
  # TODO: Beware the unsafety if accessing these fields if we end up using multiple threads.
  port = 51337 # TODO: Magic number. Ideally would want listening port number to be configurable per peer.
  peers = dict()  # A mapping from UUID to IP address (peer user ID as well?).
  peer_file = 0 # Non-volatile storage for peer data.
  # FIXME: Need to use OpenSSL from the command line to generate X.509 key pairs that can be used by the `ssl` package,
  #  then scrape just the key data from those files for use with PyCrypto.
  #  See https://stackoverflow.com/questions/12911373/how-do-i-use-a-x509-certificate-with-pycrypto 
  private_key_file = 0
  public_key_file = 0
  encryption = 0
  
  def __init__(self, directory=os.getcwd()):
    # Get the encryption object
    self.encryption = client_encryption.ClientEncryption(directory)
    
    self.private_key_file = self.encryption.private_key_loc
    self.public_key_file = self.encryption.public_key_loc
    
    self.peer_file = os.path.join(directory,'peer_file.pickle')
    if os.path.isfile(self.peer_file):
      with open(self.peer_file, 'r') as f:
        self.peers = cPickle.load(f)
    else:
      with open(self.peer_file, 'w') as f: # Create the peer mapping file if it doesn't exist.
        cPickle.dump(self.peers, f)
        
  # Ensure that each time the peer mappings are updated, the changes are stored to disk
  def update_peers(self, uuid, value):
    peers_new = self.peers.copy()
    peers_new[uuid] = value
    with open(self.peer_file, 'w') as f:
      cPickle.dump(peers_new, f)
    self.peers = peers_new
    
  def connect_to_peer(self, uuid):
    # FIXME: Raises `KeyError` exception on invalid UUID.
    ip = self.peers[uuid]
    # FIXME: Not sure if SSL actually requires the client's key info.
    s = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_SSLv3)
    s.connect((ip, self.port))
    return s
  
  def create_listening_socket(self):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(('', self.port))
    return s

  def test_client(self, peer_ip):
    # Unsafe manipulation of peer mappings, do not duplicate.
    self.peers[-1] = peer_ip
    s = self.connect_to_peer(-1)
    print 'Peer Client: Connected to peer, transmitting important data twice.'
    s.write('oh hai')
    s.write('oh hai')
    s.close()
    
  def test_server(self):
    s_listener = self.create_listening_socket()
    s_listener.listen(1)
    s_base, ip = s_listener.accept()
    print 'Peer Server: A peer is attempting to connect'
    s_secured = ssl.wrap_socket(s_base, server_side=True, keyfile=self.private_key_file, certfile=self.public_key_file, ssl_version=ssl.PROTOCOL_SSLv3)
    print 'Peer Server: Data received from peer; displaying decrypted:'+s_secured.recv(4096)
    print 'Peer Server: Data received from peer; displaying encrypted:'+s_base.recv(4096)
    s_secured.close()
    s_base.close()
    s_listener.close()
    
    
if __name__ == '__main__':
  print 'Executing peer connection test.'
  import threading
  client = Peer()
  server = Peer()
  
  t1 = threading.Thread(target=server.test_server, args=())
  t2 = threading.Thread(target=client.test_client, args=('localhost',))
  t1.start()
  t2.start()
  t2.join()
  t1.join()
  
  