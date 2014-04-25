# requires pycrypto, a library that can do encryption stuffs

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES3
import os, random, string, pickle, mt, mt_pickling, subprocess

class ClientEncryption:  
  #path name for key files/merkle trees, etc.
  backup_path = 'bookkeeping'
  personal_path = 'personal'
  files_path = 'files'
  # take a UUID and return the location for the private key file
  def private_foreign_key_loc(self, uuid):
      return os.path.join(self.directory, uuid, self.backup_path, "private_key.ppk")
  # take a UUID and return the location for the public key file
  def public_foreign_key_loc(self, uuid):
      return os.path.join(self.directory, uuid, self.backup_path, "public_key.PEM")
  # take a UUID and return the location for the personal encrypter file
  def personal_foreign_encrypter_loc(self, uuid):
      return os.path.join(self.directory, uuid, self.backup_path, "personal_encrypter.txt")
  # take a UUID and return the location for the revision number file
  def foreign_rev_no_loc(self, uuid):
      return os.path.join(self.directory, uuid, self.backup_path, "rev_no.txt")
  # take a UUID and return the location of their files.
  def foreign_files_loc(self,uuid):
      return os.path.join(self.directory, uuid, self.files_path)

  # create merkle tree and store
  def make_personal_mt(self):
      mtree = mt.MarkleTree(self.files_loc)
      mt_pickling.pickle_data(mtree,self.mt_loc)
      return
  # get personal merkle tree
  def get_personal_mt(self):
      mt_pickling.unpickle_data(self.mt_loc)
  # take a UUID and return the merkle tree for all of their files
  def get_foreign_mt(self,uuid):
      return mt.MarkleTree(self.foreign_files_loc(uuid))


  def generate_public_keypair(self):
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    with open(self.private_key_loc, 'w') as f_private:
      f_private.write(key.exportKey())
    with open(self.public_key_loc, 'w') as f_public:
      f_public.write(key.publickey().exportKey())

  # Use OpenSSL's CLI to generate an X.509 from the existing RSA private key
  # Adapted from http://stackoverflow.com/a/12921889 and http://stackoverflow.com/a/12921889
  def generate_x509_cert(self):
    subprocess.check_call('openssl req -new -batch -x509 -nodes -days 3650 -key ' +
                          self.private_key_loc +
                          ' -out ' + self.x509_cert_loc,
                          shell=True)    
    
  # initialized pubic and private key of personal computer
  def __init__(self, directory=os.getcwd()):
    
      # Set up file locations
      self.directory = directory
      self.personal_path_full = os.path.join(self.directory, self.personal_path)
      self.private_key_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "private_key.ppk")
      self.public_key_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "public_key.PEM")
      self.x509_cert_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "x509.PEM")
      self.personal_encrypter_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "personal_encrypter.txt")
      self.rev_no_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "rev_no.txt")
      self.mt_loc = os.path.join(self.directory, self.personal_path, self.backup_path, "mtree.mt")
      self.files_loc = os.path.join(self.directory, self.personal_path, self.files_path)
      
      if(os.path.isdir(self.directory) != True):
          os.makedirs(self.directory)
      if(os.path.isdir(os.path.join(self.directory, self.personal_path)) != True):
          os.makedirs(os.path.join(self.directory, self.personal_path))
      if(os.path.isdir(self.files_loc) != True):
          os.makedirs(self.files_loc)
      if(os.path.isdir(os.path.join(self.directory, self.personal_path, self.backup_path)) != True):
          os.makedirs(os.path.join(self.directory, self.personal_path, self.backup_path))
          
      # Generate the RSA key pair and certificate if they don't exist
      if not (os.path.isfile(self.private_key_loc) and os.path.isfile(self.public_key_loc)):
        self.generate_public_keypair()
        self.generate_x509_cert()
      
      f_personal = open(self.personal_encrypter_loc, 'w')
      f_rev = open(self.rev_no_loc, 'w')
      
      f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)))
      f_personal.write(Random.get_random_bytes(8))
      f_rev.write('1')

      f_personal.close()
      f_rev.close();

      
      return
  
  # initialize public and private keys of a foreign computer given the uuid.
  #this is for testing purposes ONLY!!!!
  def init_remote(self, uuid):
      random_generator = Random.new().read
      key = RSA.generate(1024, random_generator)
      if(os.path.isdir(self.directory) != True):
          os.makedirs(self.directory)
      f_private = open(self.private_foreign_key_loc(uuid), 'w')
      f_public = open(self.public_foreign_key_loc(uuid), 'w')
      f_personal = open(self.personal_foreign_encrypter_loc(uuid), 'w')
      f_rev = open(self.foreign_rev_no_loc(uuid), 'wb')
      f_private.write(key.exportKey())
      f_public.write(key.publickey().exportKey())
      f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)))
      f_personal.write(Random.get_random_bytes(8))
      pickle.dump(dict(),f_rev)
      f_private.close()
      f_public.close()
      f_personal.close()
      f_rev.close();
      return
  
  
  # read in the personal DES key used to encrypt files to be sent and decrypt downloaded files
  def read_personal_key(self):
      s = open(self.personal_encrypter_loc, 'r').read()
      personal_key = s[0:16]
      iv = s[16:24]
      return (personal_key, iv)
  
  # return personal private key
  def import_private_key(self):
      return RSA.importKey(open(self.private_key_loc, 'r').read())
  
  # return either personal public key if UUID unspecified or public key of UUID otherwise
  def import_public_key(self, uuid=''):
      if uuid == '':
          return RSA.importKey(open(self.public_key_loc, 'r').read())
      return RSA.importKey(open(self.public_foreign_key_loc(uuid), 'r').read())

  # get the revision number
  def get_rev_number(self):
    return int(open(self.rev_no_loc,'r').read())
  # update the revision number
  def inc_rev_number(self):
    rev_no = self.get_rev_no() + 1
    f = open(self.rev_no_loc,'w')
    f.write(str(rev_no))
    f.close()
    return

  # get revision number given a uuid
  def get_foreign_rev_no(self,uuid):
    return 1
  
  # get the revision number dictionary
  ########################################################################
  ####### OBSOLETE FOR NOW (ASSUME ALL FILES ARE SYNCED WHEN SYNC OCCURS)
  ########################################################################
##  def get_rev_dict(self):
##    return pickling.unpickle_data(self.rev_no_loc)
  
  ########################################################################
  ####### OBSOLETE FOR NOW (ASSUME ALL FILES ARE SYNCED WHEN SYNC OCCURS)
  ########################################################################
  # store the revision number dictionary
##  def store_rev_dict(self,rev_dict):
##    return pickling.pickle_data(rev_dict, self.rev_no_loc)
  
  ######many of the following functions are for testing purposes only#######
  
  # read personal DES key of user UUID. used for testing
  def read_foreign_personal_key(self, uuid):
      s = open(self.personal_foreign_encrypter_loc(uuid), 'r').read()
      personal_key = s[0:16]
      iv = s[16:24]
      return (personal_key, iv)
  
  # import private key of user UUID. used for testing
  def import_foreign_private_key(self, uuid):
      return RSA.importKey(open(self.private_foreign_key_loc(uuid), 'r').read())

  # update the rev_dict and return the new dict
  ########################################################################
  ####### OBSOLETE FOR NOW (ASSUME ALL FILES ARE SYNCED WHEN SYNC OCCURS)
  ########################################################################
##  def update_rev_dict(self,rev_dict,key):
##    if key in rev_dict:
##      rev_dict[key] = rev_dict[key] + 1;
##    else:
##      rev_dict[key] = 1
##    return rev_dict

      
  
  # A quick test
  def test(self):
      message = "test! Very nice!"
      private_key = self.import_private_key()
      public_key = self.import_public_key()
      signature = (private_key.sign(message, '')[0],)
      return public_key.verify(message, signature)
  
  # a more complex test where a file is encrypted using the personal encrypter, encrypted using a UUID public key
  # and then decrypted using the private key of UUID, and compared with the original encrypted message
  ##### WARNING: THIS TEST ADDS AN ENTRY INTO THE REVISION NUMBER DICT, DO NOT USE
  ##### THIS TEST WHEN IN PRODUCTION (UNLESS YOU WANT A FILE CREATED AND EDITED INTO
  ##### YOUR STUFF
  def complex_test(self):
      uuid = '100'
      self.init_remote(uuid)
      # the following is an excerpt of the Meissner bodies paragraph on Wikipedia's Reuleasux tetrahedron
      full_text = "Meissner and Schilling[2] showed how to modify the Reuleaux tetrahedron to form a surface of constant width"  # open file and write text to file, then close
      f_loc = os.path.join(self.directory, 'complex_test.txt')
      f = open(f_loc, 'w');
      f.write(full_text)
      f.close()
      # encrypt the file using local encryption key
      f_enc = self.client_encrypt(f_loc)
      f_enc_message = open(f_enc, 'r').read()
      rev_dict = self.get_rev_dict()
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
        
  # ##functions borrowed from http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
  
  # encrypts a file given the input filename, output file name, chunk size for DES, the key, and the initial value
  def encrypt_file(self, in_filename, out_filename, chunk_size, key, iv):
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
  # decrypts a file given the input filename, output file name, chunk size for DES, the key, and the initial value
  def decrypt_file(self, in_filename, out_filename, chunk_size, key, iv):
      des3 = DES3.new(key, DES3.MODE_CFB, iv) 
      with open(in_filename, 'r') as in_file:
          with open(out_filename, 'w') as out_file:
              while True:
                  chunk = in_file.read(chunk_size)
                  if len(chunk) == 0:
                      break
                  out_file.write(des3.decrypt(chunk))
  
  
  # ##back to stuff I wrote
  
  # take a encrypted file location and UUID and encrypt the file using their public key
  def public_key_encrypt(self, f_enc, uuid):
      public_key = self.import_public_key(uuid)
      return public_key.encrypt(open(f_enc, 'r').read(), 32)
  
  # encrypte a file name so that it doesn't leak information (lol, right now it totally does)
  def encrypt_filename(self, file_name):
      return file_name + 'enc'
  # decrypt a file name that is encrypted in the manner above (same issue as above, not secure)
  def decrypt_filename(self, file_name_enc):
      return file_name_enc[0:len(file_name_enc) - 3]
  
  # encrypts a file given the file location using DES and returns the location of the encrypted file
  def client_encrypt(self, file_name):
      # first encrypt personally
      file_name_enc = self.encrypt_filename(file_name)
      (personal_key, iv) = self.read_personal_key()
      self.encrypt_file(file_name, file_name_enc, 8192, personal_key, iv)
      return file_name_enc
  
  # decrypts a file given the file location using DES and returns the location of the decrypted file
  def client_decrypt(self, file_name_enc):
      file_name = self.decrypt_filename(file_name_enc)
      (personal_key, iv) = self.read_personal_key()
      self.decrypt_file(file_name_enc, file_name, 8192, personal_key, iv)
      return file_name
  
  # take a file and an address to upload a file and send it to that place.
  ####THIS FILE DOES NOT WORK YET BC OF NO GOOGLE PROTOCOL BUFFERS YET##############
  def client_upload(self, file_name, address):
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
  
  # take a uuid, file name, file contents, revision number, and signature and encrypt using the public key of UUID
  # returning the encrypted tuple of the filename, file contents, revision number, and signature of the revision number
  def encrypt_message(self, uuid, file_enc, file_enc_message, rev_no, signature):
      public_key = self.import_public_key(uuid)
      f_enc_enc = public_key.encrypt(file_enc, 32)
      file_enc_message_enc = public_key.encrypt(file_enc_message, 32)
      rev_no_enc = public_key.encrypt(str(rev_no), 32)
      signature_enc = public_key.encrypt(str(signature[0]), 32)
      return (f_enc_enc, file_enc_message_enc, rev_no_enc, signature_enc)
  
  # take a message, which is a tuple of file name, file contents, revision number, and signature
  # and decrypt using local private key, returning the decryption of the tuple
  def decrypt_message(self, message):
      (f_enc_enc, file_enc_message_enc, rev_no_enc, signature_enc) = message
      private_key = self.import_private_key()
      f_enc = private_key.decrypt(f_enc_enc)
      file_enc_message = private_key.decrypt(file_enc_message_enc)
      rev_no = int(private_key.decrypt(rev_no_enc))
      signature = (long(private_key.decrypt(str(signature_enc))),)
      return (f_enc, file_enc_message, rev_no, signature)
  
  # request for the downloaded file from a given addresss
  #######THIS IS CURRENTLY NOT WORKING(WAITING ON GOOGLE PROTOCOL BUFFERS)##########
  def client_download(self, file_name, address):
      enc_file = self.encrypt_filename(file_name)
      # ask for the encrypted file
      enc_file_loc = 0  # download file here
      self.client_decrypt(enc_file_loc)
      # remove the encrypted file
      os.remove(enc_file_loc)
      return
  
  # ##some serverside functions
  
  # download a file that was sent from the clientuuid and store locally
  def server_download(self, client_uuid, message):
      (filename, f, ver_no, signmessage) = message
      public_key = self.import_public_key(client_uuid)
      if(public_key.verify(signmessage, str(ver_no))):
          if(ver_no > self.cur_ver_no):
              f_wr = open(filename, 'w')
              f_wr.write(f)
              f_wr.close()
  
  # send a requested file to the client.
  def server_send(self, client_uuid, file_enc):
      file_enc_message = open(file_enc, 'r').read()
      private_key = self.import_private_key()
      rng = Random.new().read
      rev_no = self.get_rev_number()
      signature = private_key.sign(str(rev_no), rng)
      message = self.encrypt_message(client_uuid, file_enc, file_enc_message, rev_no, signature)


def __main__():
  ClientEncryption().complex_test()
