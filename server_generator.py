from secp256k1 import PrivateKey, PublicKey
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base58
import uuid
import rsa
import json


class AuthWallet(object):
    def __init__(self, info):
        self.privkey, self.pubkey, self.private_key, self.public_key = self.generate_keys()
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
        with open('SERVER_PRIVATE', 'wb') as f:
            f.write(privkey.exportKey())
            f.close()
        with open('SERVER_PUBLIC', 'wb') as f:
            f.write(pubkey.exportKey())
            f.close()
        f = open('SERVER_PRIVATE', 'r')
        priv_file = f.read()
        priv = priv_file.split('\n')
        priv.remove('-----BEGIN RSA PRIVATE KEY-----')
        priv.remove('-----END RSA PRIVATE KEY-----')
        private_key = ''.join(priv)
        f.close()

        f = open('SERVER_PUBLIC', 'r')
        pub_file = f.read()
        pub = pub_file.split('\n')
        pub.remove('-----BEGIN PUBLIC KEY-----')
        pub.remove('-----END PUBLIC KEY-----')
        public_key = ''.join(pub)
        f.close()
        
        return privkey, pubkey, private_key, public_key

    @staticmethod
    def generate_address(public_key):
        public_key_bi = public_key.encode()
        addr_sha256 = hashlib.sha256(public_key_bi).digest()
        h = hashlib.new('ripemd160')
        h.update(addr_sha256)
        head_added = b'0' + h.digest()
        tail = hashlib.sha256(hashlib.sha256(head_added).digest()).digest()[:4]
        address = base58.b58encode(head_added + tail)
        with open('SERVER_ADDRESS', 'w') as f:
            f.write(address)
            f.close()
        return address

def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0,11,2)])


MAC = get_mac_address()

info = {
    'MAC': MAC,
    'Username': 'WiBlock Server',
    'Email': 'root@root.com',
    'Tel': '000000',
    'Message': 'Official Server',
}

wallet = AuthWallet(info=info)
address = wallet.address

