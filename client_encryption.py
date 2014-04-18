#requires pycrypto, a library that can do encryption stuffs

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES3
import os, random, string

directory = "C:\\Users\\Dmitri\\distributed_dropbox\\"
private_key_loc = directory + "private_key.ppk"
public_key_loc = directory + "public_key.PEM"
personal_encrypter_loc = directory + "personal_encrypter.txt"
rev_no_loc = directory + "rev_no.txt"


# initialized pubic and private key of personal computer
def init():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    if(os.path.isdir(directory) != True):
        os.makedirs(directory)
    f_private = open(private_key_loc,'w')
    f_public = open(public_key_loc,'w')
    f_personal = open(personal_encrypter_loc,'w')
    f_rev = open(rev_no_loc,'w')
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

def read_personal_key():
    s = open(personal_encrypter_loc,'r').read()
    personal_key = s[0:16]
    iv = s[16:24]
    return (personal_key,iv)

def import_private_key():
    return RSA.importKey(open(private_key_loc, 'r').read())

def import_public_key(uuid = ''):
    if uuid == '':
        return RSA.importKey(open(public_key_loc, 'r').read())
    return RSA.importKey(open(uuid + '_' + public_key_loc, 'r').read())

def get_rev_number():
    f_rev = open(rev_no_loc,'r')
    rev_no = int(f_rev.read())
    f_rev.close()
    f_rev = open(rev_no_loc,'w')
    f_rev.write(str(rev_no + 1))
    f_rev.close()
    return rev_no


#A quick test
message = "test! Very nice!"
private_key = import_private_key()
public_key = import_public_key()
signature = private_key.sign(message,'')
public_key.verify(message,signature)



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

filename = 'C:\\Users\\Dmitri\\distributed_dropbox\\test.txt'
client_encrypt(filename)
client_decrypt(filename_enc)
###back to stuff I wrote
def encrypt_filename(file_name):
    return file_name +'enc'
def decrypt_filename(file_name_enc):
    return file_name_enc[0:len(file_name_enc)-3]
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
    #read revision number
    rev_no = get_rev_number()
    #read private key in
    private_key = import_private_key()
    rng = Random.new().read
    signature = private_key.sign(str(rev_no),rng)
    #send tuple of file and signature
    return
    
def client_download(file_name,address):
    enc_file = encrypt_filename(file_name)
    #ask for the encrypted file
    enc_file_loc = 0#download file here
    client_decrypt(enc_file_loc)
    #remove the encrypted file
    os.remove(enc_file_loc)
    return

###some serverside functions
def server_download(client_uuid,message):
    (filename,f,signmessage,ver_no) = message
    public_key = import_public_key(client_uuid)
    if(public_key.verify(signmessage,str(ver_no))):
        if(ver_no > cur_ver_no):
            f_wr = open(filename,'w')
            f_wr.write(f)
            f_wr.close()

def __main__():
    if(os.path.isdir(directory) != True):
       init()
