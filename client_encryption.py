# requires pycrypto, a library that can do encryption stuffs

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES3
import os, random, string, pickle, mt, mt_pickling, subprocess

class ClientEncryption:  
  #path name for key files/merkle trees, etc.
  backup_path = 'bookkeeping'
  #directory name for personal files (including keys)
  personal_path = 'personal'
  #directory name for the path of files to store remotely
  files_path = 'files'

  ### functions to get foreign file paths
  
  def private_foreign_key_loc(self, uuid):
    """Get a foreign private key location given a UUID.
    Generally used only for testing purposes."""
    return os.path.join(self.directory, uuid, self.backup_path, \
                          "private_key.ppk")
  
  def public_foreign_key_loc(self, uuid):
    """Get a foreign key location given a UUID"""
    return os.path.join(self.directory, uuid, self.backup_path, \
                        "public_key.PEM")
  
  def personal_foreign_encrypter_loc(self, uuid):
    """Get a foreign encrypter file location given a UUID.
    Generally used only for testing."""
    return os.path.join(self.directory, uuid, self.backup_path, \
                        "personal_encrypter.txt")

  def foreign_rev_no_loc(self, uuid):
    """Get a personal foreign revision number file location given a UUID.
    Generally used only for testing."""
    return os.path.join(self.directory, uuid, self.backup_path, "rev_no.txt")

  def foreign_files_loc(self,uuid):
    """Get the file location for a peer's files given a UUID."""
    return os.path.join(self.directory, uuid, self.files_path)

  def foreign_backup_loc(self,uuid):
    """Get the file location for a foriegn user's backup files given a UUID."""
    return os.path.join(self.directory, uuid, self.backup_path)



  ### Merkle tree functions
    
  def make_personal_mt(self):
    """Make a Merkle tree for the self's directory and store data."""
    mtree = mt.MarkleTree(self.files_loc)
    mt_pickling.pickle_data(mtree,self.mt_loc)
    return
  
  def get_personal_mt(self):
    """Get the stored personal Merkle Tree"""
    mt_pickling.unpickle_data(self.mt_loc)
    return

  def produce_personal_mt(self,salt=''):
    """Produce a personal Merkle tree, include salt if wanted."""
    return mt.MarkleTree(self.files_loc,salt)

  def get_foreign_mt(self,uuid, salt=''):
    """take a UUID and return the merkle tree for all of their files,
    salt optionally"""
    return mt.MarkleTree(self.foreign_files_loc(uuid), salt='')
  

  ### revision number functions

  def get_rev_number(self):
    """Get the revision number of the personal file system."""
    return int(open(self.rev_no_loc,'r').read())
  
  def inc_rev_number(self):
    """Increment the revision number of the personal file system."""
    rev_no = self.get_rev_no() + 1
    f = open(self.rev_no_loc,'w')
    f.write(str(rev_no))
    f.close()
    return

  def get_foreign_rev_no(self,uuid):
    """Take a uuid and return the tuple message (revision number,
    tophash, and signature)"""
    return mt_pickling.unpickle_data(self.foreign_rev_no_loc())

  def store_foreign_rev_no(self,uuid,tup):
    """Take a uuid and tuple message (revision number, tophash,
    and signature) and store locally"""
    return mt_pickling.pickle_data(tup,self.foreign_rev_no_loc())


  ### generating personal files functions
    
  def generate_public_keypair(self):
    """Produce a public and private key"""
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    with open(self.private_key_loc, 'w') as f_private:
      f_private.write(key.exportKey())
    with open(self.public_key_loc, 'w') as f_public:
      f_public.write(key.publickey().exportKey())

  def generate_x509_cert(self):
    """Use OpenSSL's CLI to generate an X.509 from the existing RSA private key

    Adapted from http://stackoverflow.com/a/12921889 and http://stackoverflow.com/a/12921889"""
    subprocess.check_call('openssl req -new -batch -x509 -nodes -days 3650 -key ' +
                          self.private_key_loc +
                          ' -out ' + self.x509_cert_loc,
                          shell=True)

  def generate_encrypter(self):
    """Generate a personal encryption file, which is both the DES3 key and
    IV (initial value)."""
    f_personal = open(self.personal_encrypter_loc, 'w')
    f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)))
    f_personal.write(Random.get_random_bytes(8))
    f_personal.close()
    return

  def generate_rev_no(self):
    """Generate a revision number file"""
    f_rev = open(self.rev_no_loc, 'w')  
    f_rev.write('1')
    f_rev.close()
    return

  ### Initialization of files personally and for peers

  def __init__(self, directory=os.getcwd()):
    """Initialize a personal directory for user. Creates public and
    private keys, encryption and revision number files."""
    # Set up file locations
    self.directory = directory
    self.personal_path_full = os.path.join(self.directory, self.personal_path)
    self.files_loc = os.path.join(self.personal_path_full, self.files_path)
    self.backup_files_loc = os.path.join(self.personal_path_ful, \
                                         self.backup_path)
    self.private_key_loc = os.path.join(self.backup_files_loc, \
                                        "private_key.ppk")
    self.public_key_loc = os.path.join(self.backup_files_loc, "public_key.PEM")
    self.x509_cert_loc = os.path.join(self.backup_files_loc, "x509.PEM")
    self.personal_encrypter_loc = os.path.join(self.backup_files_loc, \
                                               "personal_encrypter.txt")
    self.rev_no_loc = os.path.join(self.backup_files_loc, "rev_no.txt")
    self.mt_loc = os.path.join(self.backup_files_loc, "mtree.mt")
    
    #check to make sure file directories exist
    if(os.path.isdir(self.directory) != True):
      os.makedirs(self.directory)
    if(os.path.isdir(self.personal_path_full) != True):
      os.makedirs(self.personal_path_full)
    if(os.path.isdir(self.files_loc) != True):
      os.makedirs(self.files_loc)
    if(os.path.isdir(self.backup_files_loc) != True):
      os.makedirs(self.backup_files_loc)
          
    # Generate the RSA key pair and certificate if they don't exist
    if not (os.path.isfile(self.private_key_loc) and \
            os.path.isfile(self.public_key_loc)):
      self.generate_public_keypair()
      self.generate_x509_cert()

    # generate personal encrypter file if it doesn't exist
    if not os.path.isfile(self.personal_encrypter_loc):
      self.generate_encrypter()

    # generate revision number if doesn't exist
    if not os.path.isfile(self.rev_no_loc):
      self.generate_rev_no()
      
    return
    
  def init_remote(self, uuid,validation_tup):
    """Initialize the directory of the given uuid and store the validation
    tuple for the revision number. Assume that the public key of the uuid
    is already stored, given that the uuid is made by shortening public key
    to directory-allowable characters."""
    if(os.path.isdir(os.path.join(self.directory, uuid)) != True):
      os.makedirs(os.path.join(self.directory, uuid))
    if(os.path.isdir(os.path.join(self.directory, uuid, self.backup_path)) !=\
       True):
      os.makedirs(os.path.join(self.directory, uuid, self.backup_path))
    if(os.path.isdir(os.path.join(self.directory, uuid, self.files_path)) != \
       True):
      os.makedirs(os.path.join(self.directory, uuid, self.files_path))
    self.store_foreign_rev_no(uuid,validation_tup)
    return


  ### Interactions between peers

  def peer_download(self,f_loc_enc,f_message_enc):
    """Takes in message and uses personal key to decrypt and then store file."""
    self.writefile(os.path.join(self.personal_files_loc(),f_loc_enc),\
                   f_message_enc)
    f_loc = self.client_decrypt(f_loc_enc)
    os.remove(f_loc_enc)
    return
  
  def read_personal_key(self):
    """Read in the personal DES key used to encrypt files to be sent and decrypt
    downloaded files."""
    s = open(self.personal_encrypter_loc, 'r').read()
    personal_key = s[0:16]
    iv = s[16:24]
    return (personal_key, iv)
  
  def import_private_key(self):
    """Get the personal private key"""
    return RSA.importKey(open(self.private_key_loc, 'r').read())

  def import_public_key(self, uuid=''):
    """Get public key of either the user (if the uuid is unspecified) or the
    uuid."""
    if uuid == '':
      return RSA.importKey(open(self.public_key_loc, 'r').read())
    return RSA.importKey(open(self.public_foreign_key_loc(uuid), 'r').read())

  def changed_personal_file_directory(self):
    """Check to see if personal files have been updated. If so, update Merkle
    tree and return True. return False otherwise."""
    mtree = mt.MarkleTree(self.files_loc)
    mtreeOld = self.get_personal_mt()
    if mtree._tophash != mtreeOld._tophash:
      self.inc_rev_number()
      self.make_personal_mt()
      return True
    return False
  
   
  ######many of the following functions are for testing purposes only#######
  
  # 
  def read_foreign_personal_key(self, uuid):
    """read personal DES key of user UUID. used for testing purposes."""
    s = open(self.personal_foreign_encrypter_loc(uuid), 'r').read()
    personal_key = s[0:16]
    iv = s[16:24]
    return (personal_key, iv)
  
  # 
  def import_foreign_private_key(self, uuid):
    """import private key of user UUID. used for testing purposes."""
    return RSA.importKey(open(self.private_foreign_key_loc(uuid), 'r').read())

  ### Writing to file functions
  
  # take a file location and message and write to the file
  def writefile(self,f_loc,f_message):
    f = open(f_loc,'w')
    f.write(f_message)
    f.close()
    return
      
  def write_pubkey(self,uuid,f_message):
    f_loc = self.public_foreign_key_loc(uuid)
    self.writefile(f_loc, f_message)
    return

  ### Test functions
 
  # A quick test
  def test(self):
      message = "test! Very nice!"
      private_key = self.import_private_key()
      public_key = self.import_public_key()
      signature = (private_key.sign(message, '')[0],)
      return public_key.verify(message, signature)
  
  # a more complex test where a file is encrypted using the personal encrypter, 
  # encrypted using a UUID public key and then decrypted using the private key 
  # of UUID, and compared with the original encrypted message.
  ##### WARNING: THIS TEST ADDS AN ENTRY INTO THE REVISION NUMBER DICT, DO NOT
  ##### USE THIS TEST WHEN IN PRODUCTION (UNLESS YOU WANT A FILE CREATED AND
  ##### EDITED INTO YOUR STUFF
  def complex_test(self):
      uuid = '100'
      self.init_remote_test(uuid)
      # the following is an excerpt of the Meissner bodies paragraph on Wikipedia's Reuleasux tetrahedron
      full_text = "Meissner and Schilling[2] showed how to modify the Reuleaux tetrahedron to form a surface of constant width"  # open file and write text to file, then close
      f_loc = os.path.join(self.directory, 'complex_test.txt')
      f = open(f_loc, 'w');
      f.write(full_text)
      f.close()
      # encrypt the file using local encryption key
      f_enc = self.client_encrypt(f_loc)
      f_enc_message = open(f_enc, 'r').read()
      rev_dict = self.get_rev_number()
      rev_no = 1
      rng = Random.new().read
      private_key = self.import_private_key()
      signature = private_key.sign(str(rev_no), rng)
      public_enc_message = self.public_key_encrypt(f_enc, uuid)
      private_foreign_key = self.import_foreign_private_key(uuid)
      dec_message = private_foreign_key.decrypt(public_enc_message)
      if(dec_message != f_enc_message):
          print("Whaat, this didn't work!")
          print("decrypted message: " + dec_message + '\n')
          print("original encrypted message: " + f_enc_message)
      else:
          print("cool, encryption and decryption worked");
      return
        
  ### functions borrowed from http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
  
  def encrypt_file(self, in_filename, out_filename, chunk_size, key, iv):
    """encrypts a file given the input filename, output file name, chunk size
    for DES, the key, and the initial value"""
    des3 = DES3.new(key, DES3.MODE_CFB, iv)
    with open(in_filename, 'r') as in_file:
      with open(out_filename, 'w') as out_file:
        while True:
          chunk = in_file.read(chunk_size)
          if len(chunk) == 0:
            break
          elif len(chunk) % 16 != 0:
            chunk += ' ' * (16 - len(chunk) % 16)
            out_file.write(des3.encrypt(chunk))
  
  def decrypt_file(self, in_filename, out_filename, chunk_size, key, iv):
    """decrypts a file given the input filename, output file name, chunk size
    for DES, the key, and the initial value"""
    des3 = DES3.new(key, DES3.MODE_CFB, iv) 
    with open(in_filename, 'r') as in_file:
      with open(out_filename, 'w') as out_file:
        while True:
          chunk = in_file.read(chunk_size)
          if len(chunk) == 0:
            break
          out_file.write(des3.decrypt(chunk))
  
  
  ##back to stuff I wrote
  
  def public_key_encrypt(self, f_enc, uuid):
    """take a encrypted file location and UUID and encrypt the file using their
    public key"""
    public_key = self.import_public_key(uuid)
    return public_key.encrypt(open(f_enc, 'r').read(), 32)
  # Not actually that secure for file.
  def encrypt_filename(self, file_name):
    """encrypte a file name so that it doesn't leak information"""
    return file_name + 'enc'
  #  (same issue as above, not secure)
  def decrypt_filename(self, file_name_enc):
    """decrypt a file name that is encrypted in the manner above"""
    return file_name_enc[0:len(file_name_enc) - 3]
  
  def client_encrypt(self, file_name):
    """encrypts a file given the file location using DES and returns the
    location of the encrypted file"""
    # first encrypt personally
    file_name_enc = self.encrypt_filename(file_name)
    (personal_key, iv) = self.read_personal_key()
    self.encrypt_file(file_name, file_name_enc, 8192, personal_key, iv)
    return file_name_enc
  
  def client_decrypt(self, file_name_enc):
    """decrypts a file given the file location using DES and returns the
    location of the decrypted file."""
    file_name = self.decrypt_filename(file_name_enc)
    (personal_key, iv) = self.read_personal_key()
    self.decrypt_file(file_name_enc, file_name, 8192, personal_key, iv)
    return file_name
  
  # take a file and an address to upload a file and send it to that place.
  ####THIS FILE DOES NOT WORK YET BC OF NO GOOGLE PROTOCOL BUFFERS YET##############
  def client_upload(self, file_name, address):
      print "client_upload was called."
      enc_file = self.client_encrypt(file_name)
      # read revision number
      rev_no = self.get_rev_number()
      self.inc_rev_number()
      # read private key in
      private_key = self.import_private_key()
      rng = Random.new().read
      tophash = self.get_personal_mt()._tophash
      signature = private_key.sign(str((rev_no,tophash)), rng)
      # send tuple of filename, file message, revision number, and signature
      return
  
  def encrypt_message(self, uuid, file_enc, file_enc_message, \
                      rev_no, tophash, signature):
    """take a uuid, file name, file contents, revision number, and signature
    and encrypt using the public key of UUID returning the encrypted tuple of
    the filename, file contents, revision number, and signature of the revision
    number"""
    public_key = self.import_public_key(uuid)
    f_enc_enc = public_key.encrypt(file_enc, 32)
    file_enc_message_enc = public_key.encrypt(file_enc_message, 32)
    rev_no_enc = public_key.encrypt(str(rev_no), 32)
    tophash_enc = public_key.encrypt(str(tophash), 32)
    signature_enc = public_key.encrypt(str(signature[0]), 32)
    return (f_enc_enc, file_enc_message_enc, rev_no_enc, tophash, signature_enc)
  
  def decrypt_message(self, message):
    """take a message, which is a tuple of file name, file contents, revision
    number, and signature and decrypt using local private key, returning the
    decryption of the tuple"""
    (f_enc_enc, file_enc_message_enc, rev_no_enc, tophash_enc, signature_enc) = message
    private_key = self.import_private_key()
    f_enc = private_key.decrypt(f_enc_enc)
    file_enc_message = private_key.decrypt(file_enc_message_enc)
    rev_no = int(private_key.decrypt(rev_no_enc))
    tophash = long(private_key.decrypt(tophash_enc))
    signature = (long(private_key.decrypt(str(signature_enc))),)
    return (f_enc, file_enc_message, rev_no, tophash, signature)
  
  # request for the downloaded file from a given addresss
  #######THIS IS CURRENTLY NOT WORKING(WAITING ON GOOGLE PROTOCOL BUFFERS)##########
  def client_download(self, file_name, address):
      print "client_download called"
      enc_file = self.encrypt_filename(file_name)
      # ask for the encrypted file
      enc_file_loc = 0  # download file here
      self.client_decrypt(enc_file_loc)
      # remove the encrypted file
      os.remove(enc_file_loc)
      return

  def prepare_upload(self, filename, uuid):
    """takes a filename and address and prepares an encrypted message sent to
    UUID"""
    enc_file = self.client_encrypt(filename)
    enc_file_message = open(enc_file,'r').read()
    # Increment revision number.
    self.inc_rev_number()
    signature, rev_no, tophash = self.get_signed_revision()
    encrypted_message = self.encrypt_message(uuid, enc_file, enc_file_message, rev_no, tophash, signature)
    return encrypted_message

  def get_signed_revision(self):
    """get a signature for the hash tree, revision number, and merkle tree"""
    # read revision number
    rev_no = self.get_rev_number()
    # read private key in
    private_key = self.import_private_key()
    rng = Random.new().read
    tophash = self.get_personal_mt()._tophash
    signature = private_key.sign(str((rev_no,tophash)), rng)
    return signature, rev_no, tophash

  def download_message(self, uuid, message):
    """function that takes an encrypted message containing a file to store and
    then stores locally"""
    (f_enc, file_enc_message, rev_no, tophash, signature) = \
            self.decrypte_message(message)
    private_key = self.import_private_key()
    dec_sig = private_key.decrypt(signature)
    #ensure that the signature matches what we expect
    if(dec_sig == str((rev_no,tophash))):
      #Assume that the file can be uploaded at this point, update all files to reflect this
      file_loc = os.path.join(self.foreign_files_loc(uuid),f_enc);
      self.writefile(file_loc,file_enc_message)
      self.store_foreign_rev_no(uuid,(rev_no,tophash,signature))
    else:
      #throw some kind of error saying this is not a valid signature
      print "this is not a valid signature!"
    return

  
  ###some serverside functions
  
  def server_download(self, client_uuid, message):
    """download a file that was sent from the clientuuid and store locally."""
    print "server_download called."
    (filename, f, ver_no, signmessage) = message
    public_key = self.import_public_key(client_uuid)
    if(public_key.verify(signmessage, str(ver_no))):
      if(ver_no > self.cur_ver_no):
        f_wr = open(filename, 'w')
        f_wr.write(f)
        f_wr.close()

  def server_send(self, client_uuid, file_enc):
    """send a requested file to the client."""
    print "server_send called."
    file_enc_message = open(file_enc, 'r').read()
    private_key = self.import_private_key()
    rng = Random.new().read
    rev_no = self.get_rev_number()
    signature = private_key.sign(str(rev_no), rng)
    message = self.encrypt_message(client_uuid, file_enc, file_enc_message, rev_no, signature)
    return

  # 
  def is_peer_rev_no_newer(self, client_uuid, peer_uuid, tup):
    """check to see whether uuid's signature is newer or not"""
    (rev_no, tophash, sig) = tup
    public_key = self.import_public_key(client_uuid)
    #make sure that the signaturue is valid
    if (str((rev_no,tophash)) == public_key.decrypt(sig)):
      (rev_no_personal,tophash_personal,sig_personal) = self.get_foreign_rev_no(client_uuid)
      return rev_no < rev_no_personal


  #testing suite

  def init_remote_test(self, uuid):
    """initialize public and private keys of a foreign computer given the uuid.
    This is for testing purposes ONLY!!!!"""
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)

    if(os.path.isdir(os.path.join(self.directory,uuid)) != True):
      os.makedirs(os.path.join(self.directory,uuid))
    if(os.path.isdir(self.foreign_files_loc(uuid)) != True):
      os.makedirs(self.foreign_files_loc(uuid))
    if(os.path.isdir(self.foreign_backup_loc(uuid)) != True):
      os.makedirs(self.foreign_backup_loc(uuid))
    f_private = open(self.private_foreign_key_loc(uuid), 'w')
    f_public = open(self.public_foreign_key_loc(uuid), 'w')
    f_personal = open(self.personal_foreign_encrypter_loc(uuid), 'w')
    f_rev = open(self.foreign_rev_no_loc(uuid), 'wb')
    f_private.write(key.exportKey())
    f_public.write(key.publickey().exportKey())
    f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)))
    f_personal.write(Random.get_random_bytes(8))
    f_rev.write('1')
    f_private.close()
    f_public.close()
    f_personal.close()
    f_rev.close()
    return

  def init_peer_test(self):
    """initialize a peer, print all locations"""
    uuid = '200'
    self.init_remote_test(uuid)
    print self.private_foreign_key_loc(uuid)
    print self.public_foreign_key_loc(uuid)
    print self.personal_foreign_encrypter_loc(uuid)
    print self.foreign_rev_no_loc(uuid)
    print self.foreign_files_loc(uuid)
    print self.foreign_backup_loc(uuid)
    
  def init_test(self):
    """initialize self and print all locations"""
    self.__init__()
    print self.directory
    print self.personal_path_full
    print self.private_key_loc
    print self.public_key_loc
    print self.x509_cert_loc
    print self.personal_encrypter_loc
    print self.rev_no_loc
    print self.mt_loc
    print self.files_loc
    
if __name__ == '__main__':
  ClientEncryption().complex_test()
  ClientEncryption().init_peer_test()
  ClientEncryption().init_test()
