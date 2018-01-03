
################### BEGIN SOKCET #########################

import socket,select,sys,threading,time

HOST='localhost'
PORT=4000
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))
s.setblocking(0)

REGISTERED = False
wallet = None

def handle_recv(msg_recv):
    msg_encoded = msg_recv.encode()
    dic_data = json.loads(msg_encoded)

    if 'success_message' in dic_data:
        #Todo connect and check if TX is broadcasted
        print('Connect Successfully!')
        wallet.auth_coin = None
        return
    elif 'fail_message' in dic_data:
        return

    if 'auth_coin' in dic_data:
        #Todo store AuthCoin
        wallet.auth_coin = dic_data
        with open('AUTHCOIN', 'wb') as ac_f:
            ac_f.write(msg_encoded)
            ac_f.close()
        return

    signature = wallet.privkey.sign(SHA256.new(msg_encoded).digest(), '')
    data = {}
    data['raw'] = json.loads(msg_recv)
    data['signature'] = signature
    data['auth_coin'] = wallet.auth_coin
    auth_coin_enc = wallet.auth_coin['auth_coin']
    json_auth_coin = json.loads(auth_coin_enc)
    auth_coin = b''
    for i in range(len(json_auth_coin)):
        auth_coin += wallet.privkey.decrypt(eval(json_auth_coin[str(i)]))
    auth_coin += b'}'
    auth_coin = json.loads(auth_coin.decode())
    data['id'] = auth_coin['id'] 
    speak(json.dumps(data).encode())


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
					handle_recv(astr)
		time.sleep(0.1)


t = threading.Thread(target=start_read)
t.start()


def close_sock(s):
	s.close()

############## END SOCKET #####################


from secp256k1 import PrivateKey, PublicKey
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
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
    def __init__(self, info, empty=False):
        self.auth_coin = None
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
        with open('ADDRESS', 'w') as f:
            f.write(address)
            f.close()
        return address


def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0,11,2)])


def register():
    global wallet
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



import os
files = os.listdir(os.getcwd())
if 'PRIVATE' in files and 'PUBLIC' in files:
    wallet = AuthWallet(info=None, empty=True)
    with open('PRIVATE', 'r') as priv_f:
        privkey = RSA.importKey(priv_f.read())
        wallet.privkey = privkey

        priv_f.close()

    with open('PUBLIC', 'r') as pub_f:
        pub_file = pub_f.read()
        wallet.pub_file = pub_file
        pubkey = RSA.importKey(pub_file)
        wallet.pubkey = pubkey

        pub_f.close()

    with open('ADDRESS', 'r') as addr_f:
        address = addr_f.read()
        wallet.address = address
        addr_f.close()

    with open('AUTHCOIN', 'r') as ac_f:
        auth_coin = ac_f.read()
        wallet.auth_coin = eval(auth_coin)
        ac_f.close()
    REGISTERED = True
else:
    print('==============STA REGISTER=================')
    register()
    print('===========STA REGISTRATION FINISH=========')
    REGISTERED = True


while not REGISTERED:
    time.sleep(3)

time.sleep(1)

while True:
    confirm_connect = input('Do you want to connect?(y/N)\n')
    if confirm_connect == 'y':
        message = wallet.pub_file.encode()
        #connect to AP and notifies AP public
        speak(message)
        break
    else:
        print('System will ask for connection every five seconds...')
        time.sleep(5)



