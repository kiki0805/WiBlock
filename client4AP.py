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
    def __init__(self, info):
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
        with open('PRIVATE', 'wb') as f:
            f.write(privkey.exportKey())
            f.close()
        with open('PUBLIC', 'wb') as f:
            f.write(pubkey.exportKey())
            f.close()
        f = open('PRIVATE', 'r')
        priv_file = f.read()
        priv = priv_file.split('\n')
        priv.remove('-----BEGIN RSA PRIVATE KEY-----')
        priv.remove('-----END RSA PRIVATE KEY-----')
        private_key = ''.join(priv)
        f.close()

        f = open('PUBLIC', 'r')
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
        return address


def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

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

########## ABOVE is AP WALLET GENERATOR #################

def handle_data(data):
    res = requests.post('http://127.0.0.1:5000/register', data=data)
    return res.text
    #dic_data = json.loads(data.decode())
    #
    #transaction = {'coin_type': CoinType.AuthCoin,
    #        'trans_type': TansType.CONNECT,
    #        'sender': dic_data['public_key'],
    #        'recipinent': wallet.pubkey.exportKey().decode(),
    #        'amount': 1}


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(9000).strip()
        response = handle_data(self.data)
        # just send back the same data, but upper-cased
        self.request.sendall(response.encode())

if __name__ == "__main__":
    HOST, PORT = "localhost", 4000

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
