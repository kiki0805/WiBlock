import socketserver
from CONSTANTS import CoinType, TransType
import json
import requests

from secp256k1 import PrivateKey, PublicKey
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base58
import uuid
import rsa


server_public_key = None
with open('SERVER_PUBLIC', 'r') as f:
    server_pub_file = f.read()
    server_public_key = RSA.importKey(server_pub_file)
    f.close()


class AuthWallet(object):
    def __init__(self, info, empty=False):
        if empty:
            self.privkey, self.pubkey, self.private_key, self.public_key, self.pub_file = None, None, None, None, None
            self.address = None
            self.info = None
            return
        self.privkey, self.pubkey, self.private_key, self.public_key, self.pub_file = self.generate_keys()
        self.address = self.generate_address(self.public_key)
        self.info = info
        # {
        #     'MAC': ,
        #     'Username': ,
        #     'Email': ,
        #     'Tel': ,
        #     'Message': ,
        #     ...
        # }

    @staticmethod
    def generate_keys():
        # privkey = PrivateKey()
        # pubkey = privkey.pubkey
        random_generator = Random.new().read
        privkey = RSA.generate(1024, random_generator)
        pubkey = privkey.publickey()
        with open('AP_PRIVATE', 'wb') as f:
            f.write(privkey.exportKey())
            f.close()
        with open('AP_PUBLIC', 'wb') as f:
            f.write(pubkey.exportKey())
            f.close()
        f = open('AP_PRIVATE', 'r')
        priv_file = f.read()
        priv = priv_file.split('\n')
        priv.remove('-----BEGIN RSA PRIVATE KEY-----')
        priv.remove('-----END RSA PRIVATE KEY-----')
        private_key = ''.join(priv)
        f.close()

        f = open('AP_PUBLIC', 'r')
        pub_file = f.read()
        pub = pub_file.split('\n')
        pub.remove('-----BEGIN PUBLIC KEY-----')
        pub.remove('-----END PUBLIC KEY-----')
        public_key = ''.join(pub)
        f.close()
        
        return privkey, pubkey, private_key, public_key, pub_file

    @staticmethod
    def generate_address(public_key):
        public_key_bi = public_key.encode()
        addr_sha256 = hashlib.sha256(public_key_bi).digest()
        h = hashlib.new('ripemd160')
        h.update(addr_sha256)
        head_added = b'0' + h.digest()
        tail = hashlib.sha256(hashlib.sha256(head_added).digest()).digest()[:4]
        address = base58.b58encode(head_added + tail)
        with open('AP_ADDRESS', 'w') as f:
            f.write(address)
            f.close()
        return address


def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

def register():
    MAC = get_mac_address()

    print('Fill your information...')
    print('(optional, press <Enter> to skip)')
    username = input('Username: ')
    email = input('Email: ')
    tel = input('Tel: ')
    message = input('Message: ')

    info = {
        'MAC': MAC,
        'Username': username,
        'Email': email,
        'Tel': tel,
        'Message': message,
    }

    wallet = AuthWallet(info=info)
    message = {'public_key': wallet.pub_file, 'info': info, 'address': wallet.address}
    data = json.dumps(message)
    data = data.encode()
    length = len(data)
    enc_data = {}
    import math
    for i in range(math.ceil(length / 128)):
        start = i * 128
        end = start + 128
        if end >= length:
            end = -1
        enc_data[i] = str(server_public_key.encrypt(data[start: end], 32)[0])
    #enc_data = server_public_key.encrypt(data, 32)
    handle_data(json.dumps(enc_data).encode())


wallet = None
import os
files = os.listdir(os.getcwd())
if 'AP_PRIVATE' in files and 'AP_PUBLIC' in files:
    wallet = AuthWallet(info=None, empty=True)
    with open('AP_PRIVATE', 'r') as priv_f:
        privkey = RSA.importKey(priv_f.read())
        wallet.privkey = privkey

        priv_f.close()

    with open('AP_PUBLIC', 'r') as pub_f:
        pub_file = pub_f.read()
        wallet.pub_file = pub_file
        pubkey = RSA.importKey(pub_file)
        wallet.pubkey = pubkey

        pub_f.close()

    with open('AP_ADDRESS', 'r') as addr_f:
        address = addr_f.read()
        wallet.address = address
        addr_f.close()
else:
    print('AP REGISTER...')
    register()
    print('AP REGISTRATION FINISH')

########## ABOVE is AP WALLET GENERATOR #################

def handle_data(data):
    #data_decoded = data.decode()
    #res = generate_transaction(data_decoded)
    #return res
    try:
        print('Try to decode message')
        data_decoded = data.decode()
        try:
            print('Try to decode signature')
            dic_data = json.loads(data_decoded)
            validate = verify_signature(dic_data)
            if validate:
                res = requests.post('http://127.0.0.1:5000/transactions/generate', data=data)
                res = res.text
        except:
            print('Not a dic. Regard as public_key')
            res = generate_transaction(data_decoded)
        return res
    except:
        print('Fail decode. POST to registrate.')
        res = requests.post('http://127.0.0.1:5000/register', data=data)
        return res.text


def verify_signature(tx_with_sign):
    return True


def generate_transaction(public_key):
    transaction = {'coin_type': CoinType.AuthCoin,
            'trans_type': TransType.CONNECT,
            'sender': public_key,
            'recipient': wallet.pub_file,
            'amount': 1}
    return json.dumps(transaction)


#class MyTCPHandler(socketserver.BaseRequestHandler):
#    """
#    The request handler class for our server.
#
#    It is instantiated once per connection to the server, and must
#    override the handle() method to implement communication to the
#    client.
#    """
#
#    def handle(self):
#        # self.request is the TCP socket connected to the client
#        self.data = self.request.recv(9000).strip()
#        response = handle_data(self.data)
#        # just send back the same data, but upper-cased
#        self.request.sendall(response.encode())

#HOST, PORT = "localhost", 4000

#import socket
#server_socket = socket.socket()
#server_socket.bind((HOST, PORT))
#server_socket.listen(3)
#conn, address = server

##############test socket
import socket, select
from threading import Thread


class ClientThread(Thread):

    def __init__(self,ip,port):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        print("[+] New thread started for "+ip+":"+str(port))


    def run(self):
        while True:
            data = conn.recv(9999)
            if not data: break
            response = handle_data(data)
            print(response)
            conn.send(response.encode())

TCP_IP = '0.0.0.0'
TCP_PORT = 4000
BUFFER_SIZE = 9999  # Normally 1024
threads = []

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(("0.0.0.0", 4000))
server_socket.listen(10)

read_sockets, write_sockets, error_sockets = select.select([server_socket], [], [])

while True:
    for sock in read_sockets:
        (conn, (ip,port)) = server_socket.accept()
        newthread = ClientThread(ip,port)
        newthread.start()
        threads.append(newthread)

for t in threads:
    t.join()

############test scoket


# Create the server, binding to localhost on port 9999
#with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
#    # Activate the server; this will keep running until you
#    # interrupt the program with Ctrl-C
#    server.serve_forever()

