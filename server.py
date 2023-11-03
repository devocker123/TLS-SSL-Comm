#server side
import socket
import random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

HOST = '127.0.0.1'
PORT = 65432

BLOCK_SIZE = 16

#certificate generation
def sign_certificate(public_key, ca_private_key):
    h = SHA256.new(public_key)
    signature = pkcs1_15.new(ca_private_key).sign(h)
    return signature
#certificate verification function
def verify_certificate(certificate, ca_public_key):
    h = SHA256.new(certificate["public_key"])
    try:
        pkcs1_15.new(ca_public_key).verify(h, certificate["signature"])
        return True  # Valid signature
    except (ValueError, TypeError):
        return False  # Invalid signature

####
def aes_encrypt(plain_text, key):  
    print("text to be sent: ", plain_text)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), BLOCK_SIZE))
    ct = b64encode(ct_bytes).decode('utf-8')
    return {'iv': b64encode(cipher.iv).decode('utf-8'), 'ciphertext': ct}

def aes_decrypt(enc_dict, key):  
    iv = b64decode(enc_dict['iv'])
    ct = b64decode(enc_dict['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE).decode('utf-8')

####

#generate pair of RSA keys and store them in seperate files
#part 1 key generation and storage
def generate_keys(filename_prefix):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{filename_prefix}_private_key.pem", "wb") as private_file:
        private_file.write(private_key)

    with open(f"{filename_prefix}_public_key.pem", "wb") as public_file:
        public_file.write(public_key)

# This will generate the keys only if they don't already exist
try:
    with open("server_public_key.pem", "rb") as file:
        pass#skip key generation
except FileNotFoundError:
    generate_keys("server")

#certificate signing
with open("server_private_key.pem", "rb") as ca_key_file:#ca
    ca_private_key = RSA.import_key(ca_key_file.read())

with open("server_public_key.pem", "rb") as server_key_file:
    server_public_key_content = server_key_file.read()

server_cert_signature = sign_certificate(server_public_key_content, ca_private_key)
server_certificate = {
    "public_key": server_public_key_content,
    "signature": server_cert_signature
}


s = socket.socket()
print("Socket Created")
port = 9999

s.bind((HOST, PORT))
print(f"Socket binded to {PORT}")

s.listen(3)
print("Socket is listening")

while True:
    conn, addr = s.accept()
    print(f"Connected to {addr}")
    
    # NEW: Send server's certificate instead of just the public key
    print("server sending cert")
    conn.send(str(server_certificate).encode())
    print("after sending")
    break



# Receive client's public key and send server's public key
client_public_key = conn.recv(2048).decode()
print("rcvd clients public key")
with open("server_public_key.pem", "rb") as file:
    conn.send(file.read())


#diffiehelman key exchange protocol to securely exchange the shared keys
# it generates a pair of public and private key to generate a shared secret
# class for 
class DiffieHellman:
    def __init__(self, p, g):
        self.p, self.g = p, g  # constructor
        self.private = random.randint(1, p)  # random initialization of private key
        self.public = pow(self.g, self.private, self.p)  # calculate public key based on slef private key

    def get_shared_secret(self, other_public):  # generate shared secret 
        return pow(other_public, self.private, self.p)  # based on self private key and clients public key

p = 23
g = 5
#  instance representing server side of p and g values
dh_server = DiffieHellman(p, g)

# Send server's DH public key
print("server sending DH public key")
conn.send(str(dh_server.public).encode('utf-8'))#sent in integers

# Receive client's DH public key
dh_client_public = int(conn.recv(2048).decode('UTF-8'))

# Derive shared secret
shared_secret = dh_server.get_shared_secret(dh_client_public)
print(f"Shared Secret on Server: {shared_secret}")


####
# After deriving the shared secret
shared_secret_bytes = str(shared_secret).encode('utf-8')  
derived_key = SHA256.new(shared_secret_bytes).digest()  


while True:
    # To send an encrypted message
    # Enter a message to send
    message_to_send = input("Enter a message to send: ")
    encrypted_message = aes_encrypt(message_to_send, derived_key)  
    conn.send(str(encrypted_message).encode('utf-8'))  

    # To receive and decrypt a message
    encrypted_data_received = eval(conn.recv(2048).decode('utf-8'))  
    decrypted_message = aes_decrypt(encrypted_data_received, derived_key) 
    print(f"Decrypted Message from Client: {decrypted_message}") 
    
    if decrypted_message.lower() == "goodbye":
        print("Received 'goodbye'. Exiting the loop.")
        break  

####