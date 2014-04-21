# requires pycrypto, a library that can do encryption stuffs

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES3
import os, random, string

class ClientEncryption:  
  
  # take a UUID and return the location for the private key file
  def private_foreign_key_loc(self, uuid):
      return os.path.join(self.directory, uuid + '_' + "private_key.ppk")
  # take a UUID and return the location for the public key file
  def public_foreign_key_loc(self, uuid):
      return os.path.join(self.directory, uuid + '_' + "public_key.PEM")
  # take a UUID and return the location for the personal encrypter file
  def personal_foreign_encrypter_loc(self, uuid):
      return os.path.join(self.directory, uuid + '_' + "personal_encrypter.txt")
  
  # take a UUID and return the location for the revision number file
  def foreign_rev_no_loc(self, uuid):
      return os.path.join(self.directory, uuid + '_' + "rev_no.txt")
  
  
  # initialized pubic and private key of personal computer
  def __init__(self, directory=os.getcwd()):
    
      # Set up file locations
      self.directory = directory
      self.private_key_loc = os.path.join(self.directory, "private_key.ppk")
      self.public_key_loc = os.path.join(self.directory, "public_key.PEM")
      self.personal_encrypter_loc = os.path.join(self.directory, "personal_encrypter.txt")
      self.rev_no_loc = os.path.join(self.directory, "rev_no.txt")
      
      random_generator = Random.new().read
      
      if(os.path.isdir(self.directory) != True):
          os.makedirs(self.directory)
          
      # Generate the RSA key pair if it doesn't exist
      if not (os.path.isfile(self.private_key_loc) and os.path.isfile(self.public_key_loc)):
        key = RSA.generate(1024, random_generator)
        with open(self.private_key_loc, 'w') as f_private:
          f_private.write(key.exportKey())
        with open(self.public_key_loc, 'w') as f_public:
          f_public.write(key.publickey().exportKey())
      
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
      f_rev = open(self.foreign_rev_no_loc(uuid), 'w')
      f_private.write(key.exportKey())
      f_public.write(key.publickey().exportKey())
      f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)))
      f_personal.write(Random.get_random_bytes(8))
      f_rev.write('1')
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
  
  # get the revision number and increment the value, return the unincremented value
  def get_rev_number(self):
      f_rev = open(self.rev_no_loc, 'r')
      rev_no = int(f_rev.read())
      f_rev.close()
      f_rev = open(self.rev_no_loc, 'w')
      f_rev.write(str(rev_no + 1))
      f_rev.close()
      return rev_no
  
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
  
  
  # A quick test
  def test(self):
      message = "test! Very nice!"
      private_key = self.import_private_key()
      public_key = self.import_public_key()
      signature = (private_key.sign(message, '')[0],)
      return public_key.verify(message, signature)
  
  # a more complex test where a file is encrypted using the personal encrypter, encrypted using a UUID public key
  # and then decrypted using the private key of UUID, and compared with the original encrypted message
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
      rev_no = self.get_rev_number()
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
      # read private key in
      private_key = self.import_private_key()
      rng = Random.new().read
      signature = private_key.sign(str(rev_no), rng)
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
