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
def private_foreign_key_loc(uuid):
    return directory + uuid + '_' + "private_key.ppk"

def public_foreign_key_loc(uuid):
    return directory + uuid + '_' + "public_key.PEM"

def personal_foreign_encrypter_loc(uuid):
    return directory + uuid + '_' + "personal_encrypter.txt"

def foreign_rev_no_loc(uuid):
    return directory + uuid + '_' + "rev_no.txt"


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

#initialize public and private keys of a foreign computer given the uuid.
#this is for testing purposes ONLY!!!!
def init_remote(uuid):
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    if(os.path.isdir(directory) != True):
        os.makedirs(directory)
    f_private = open(private_foreign_key_loc(uuid),'w')
    f_public = open(public_foreign_key_loc(uuid),'w')
    f_personal = open(personal_foreign_encrypter_loc(uuid),'w')
    f_rev = open(foreign_rev_no_loc(uuid),'w')
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
    return RSA.importKey(open(public_foreign_key_loc(uuid), 'r').read())

def get_rev_number():
    f_rev = open(rev_no_loc,'r')
    rev_no = int(f_rev.read())
    f_rev.close()
    f_rev = open(rev_no_loc,'w')
    f_rev.write(str(rev_no + 1))
    f_rev.close()
    return rev_no

#many of the following functions are for testing purposes only
def read_foreign_personal_key(uuid):
    s = open(personal_foreign_encrypter_loc(uuid),'r').read()
    personal_key = s[0:16]
    iv = s[16:24]
    return (personal_key,iv)

def import_foreign_private_key(uuid):
    return RSA.importKey(open(private_foreign_key_loc(uuid), 'r').read())


#A quick test
def test():
    message = "test! Very nice!"
    private_key = import_private_key()
    public_key = import_public_key()
    signature = private_key.sign(message,'')
    return public_key.verify(message,signature)

def complex_test():
    init()
    uuid = '100'
    init_remote(uuid)
    #the following is an excerpt of the Meissner bodies paragraph on Wikipedia's Reuleasux tetrahedron
    full_text = "Meissner and Schilling[2] showed how to modify the Reuleaux tetrahedron to form a surface of constant width"    #open file and write text to file, then close
    f_loc = 'C:\\Users\\Dmitri\\distributed_dropbox\\complex_test.txt'
    f = open(f_loc,'w');
    f.write(full_text)
    f.close()
    #encrypt the file using local encryption key
    f_enc = client_encrypt(f_loc)
    f_enc_message = open(f_enc,'r').read()
    rev_no = get_rev_number()
    rng = Random.new().read
    private_key = import_private_key()
    signature = private_key.sign(str(rev_no),rng)
    public_enc_message = public_key_encrypt(f_enc,uuid)
    private_foreign_key = import_foreign_private_key(uuid)
    dec_message = private_foreign_key.decrypt(public_enc_message)
    if( dec_message != f_enc_message):
        print("Whaat, this didn't work!")
        print("decrypted message: " + dec_message + '\n')
        print("original encrypted message: " + f_enc_message)
    else:
        print("cool, encryption and decryption worked");
    return
    
complex_test()

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
def public_key_encrypt(f_enc,uuid):
    public_key = import_public_key(uuid)
    return public_key.encrypt(open(f_enc,'r').read(),32)

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
    #send tuple of filename, file message, revision number, and signature
    return

def encrypt_message(uuid,file_enc,file_enc_message,rev_no,signature):
    public_key = import_public_key(uuid)
    f_enc_enc = public_key.encrypt(file_enc,32)
    file_enc_message_enc = public_key.encrypt(file_enc_message,32)
    rev_no_enc = public_key.encrypt(str(rev_no),32)
    signature_enc = public_key.encrypt(str(signature[0]))
    return (f_enc_enc,file_enc_message_enc,rev_no_enc,signature_enc)
    
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
    (filename,f,ver_no,signmessage) = message
    public_key = import_public_key(client_uuid)
    if(public_key.verify(signmessage,str(ver_no))):
        if(ver_no > cur_ver_no):
            f_wr = open(filename,'w')
            f_wr.write(f)
            f_wr.close()

def server_send(client_uuid,file_enc):
    file_enc_message = open(file_enc,'r').read()
    private_key = import_private_key()
    rng = Random.new().read
    rev_no = get_rev_number()
    signature = private_key.sign(str(rev_no),rng)
    message = encrypt_message(client_uuid,file_enc,file_enc_message,rev_no,signature)


def __main__():
    if(os.path.isdir(directory) != True):
       init()
