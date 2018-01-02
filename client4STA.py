
################### BEGIN SOKCET #########################

import socket,select,sys,threading,time

HOST='localhost'
PORT=4000
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))
s.setblocking(0)


def speak(msg):
	global s
	s.send(msg)


def start_read():
	global s
	while 1:
		rlist = [s]
		# Get the list sockets which are readable
		read_list, write_list, error_list = select.select(rlist , [], [])
		for sock in read_list:
			#incoming message from remote server
			if sock == s:
				data = sock.recv(9999)
				astr = data.decode()
				if astr != "":
					print(astr)
		time.sleep(0.1)


t = threading.Thread(target=start_read)
t.start()


def close_sock(s):
	s.close()

############## END SOCKET #####################


from secp256k1 import PrivateKey, PublicKey
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base58
import uuid
import rsa
import json


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
speak(json.dumps(enc_data).encode())



