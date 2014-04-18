#requires pycrypto, a library that can do encryption stuffs

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES3
import os

directory = "C:\\Users\\Dmitri\\distributed_dropbox\\"
private_key_loc = directory + "private_key.ppk"
public_key_loc = directory + "public_key.PEM"
personal_encrypter_loc = directory + "personal_encrypter.txt"


# initialized pubic and private key of personal computer
def init():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    if(os.path.isdir(directory) != True):
        os.makedirs(directory)
    f_private = open(private_key_loc,'w')
    f_public = open(public_key_loc,'w')
    f_personal = open(personal_encrypter_loc,'w')
    f_private.write(key.exportKey())
    f_public.write(key.publickey().exportKey())
    f_personal.write(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + Random.get_random_bytes(8))
    f_personal.write(
    f_private.close()
    f_public.close()
    f_personal.close()
    return

def read_personal_key():
    s = open(personal_encrypter_loc,'r').read()
    personal_key = s[0:8]
    iv = s[8:16]
    return (personal_key,iv)

###functions borrowed from http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

 
def encrypt_file(in_filename, out_filename, chunk_size, key, iv):
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
 
def decrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv) 
    with open(in_filename, 'r') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                out_file.write(des3.decrypt(chunk))




###back to stuff I wrote
def encrypt_filename(file_name):
    return file_name +'enc'
def decrypt_filename(file_name_enc):
    return file_name_enc[0:length(file_name_enc)-3]
def client_encrypt(file_name):
    #first encrypt personally
    file_name_enc = encrypt_filename(file_name)
    (personal_key,iv) = read_personal_key()
    encrypt_file(file_name, file_name_enc, 8192, personal_key, iv)
    return file_name_enc

def client_decrypt(file_name_enc):
    file_name = decrypt_filename(file_name_enc)
    (personal_key,iv) = read_personal_key()
    decrypt_file(file_name_enc, file_name, 8192, personal_key, iv)
    return file_name

def client_upload(file_name,address):
    enc_file = client_encrypt(file_name)
    #somehow send encrypted file to the address
    return
    
def client_download(file_name,address):
    enc_file = encrypt_filename(file_name)
    #ask for the encrypted file
    enc_file_loc = 0#download file here
    client_decrypt(enc_file_loc)
    #remove the encrypted file
    os.remove(enc_file_loc)

def __main__():
    if(os.path.isdir(directory) != True):
       init()