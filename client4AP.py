############# options setting ####################
import sys, getopt, os
from get_host_ip import get_host_ip
from validate_port import validate_port

opts, args = getopt.getopt(sys.argv[1:], 'hp:s:')
host = get_host_ip()
socket_port = 4000
server_host = None
server_port = None

port = None
for op, value in opts:
    if op == '-p':
        server_port = eval(value)
    elif op == '-s':
        server_host = value
    elif op == '-h':
        print('Usage:\n\tpython client4AP.py -s server_host -p server_port')
        sys.exit()
    else:
        print('Unknown parameter(s).')
        sys.exit()

if not server_port:
    print('Please set server port. Use -h for help.')
    sys.exit()

if server_host == '':
    print('Please set server port. Use -h for help.')
    sys.exit()

print('Socket opens at {host}:{port}...'.format(host=host, port=str(socket_port)))


################## options setting #######################

from CONSTANTS import CoinType, TransType
import json
import requests

from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import base58
import uuid


user_public_keys = {}
server_public_key = None
with open('SERVER_PUBLIC', 'r') as f:
    server_pub_file = f.read()
    server_public_key = RSA.importKey(server_pub_file)
    f.close()


class AuthWallet(object):
    def __init__(self, info, empty=False):
        self.auth_coins = {}
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
    global wallet, server_host, server_port
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
    #Todo register for AP
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

    res = requests.post('http://{host}:{port}/register4AP'.format(host=server_host, port=server_port), data=json.dumps(enc_data).encode())
    assert 'success_message' in json.loads(res.text)

wallet = None
files = os.listdir(os.getcwd())
if 'AP_PRIVATE' in files and 'AP_PUBLIC' in files and 'AP_ADDRESS' in files:
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

def handle_data(data, ip, port):
    #return reponse and if_disconnect
    #data_decoded = data.decode()
    #res = generate_transaction(data_decoded)
    #return res
    from Crypto.Hash import SHA256
    global user_public_keys, server_host, server_port
    data_decoded = data.decode()
    
    try:
        assert data_decoded == 'Disconnect Request'
        res = json.dumps(wallet.auth_coins[(ip, port)])
        transaction = generate_transaction(user_public_keys[(ip, port)], send=True)
        signature = wallet.privkey.sign(SHA256.new(transaction.encode()).digest(), '')
        data = {}
        data['raw'] = json.loads(transaction)
        data['signature'] = signature
        res_from_server = requests.post('http://{host}:{port}/transactions/generate'.format(host=server_host, port=server_port), data=json.dumps(data).encode())
        assert res_from_server.status_code == 200
        del wallet.auth_coins[(ip, port)]
        return res, True
    except:
        pass

    try:
        dic_data = json.loads(data_decoded)
    except:
        print('Receive public_key. To generate TX')
        res = generate_transaction(data_decoded)
        user_public_keys[(ip, port)] = data_decoded
        return res, False

    if '0' in dic_data:
        print('POST to registrate...')
        res = requests.post('http://{host}:{port}/register'.format(host=server_host, port=server_port), data=data)
        return res.text, False

    print('Detected signature')
    validate = verify_signature(dic_data, ip, port)
    if not validate:
        print('Validation Fail!')
        #Disconnect
        message = {'fail_message': 'Validation Fail!'}
        return json.dumps(message), False
    res = requests.post('http://{host}:{port}/transactions/generate'.format(host=server_host, port=server_port), data=data)
    return res.text, False



def verify_signature(tx_with_sign, ip, port):
    global user_public_keys, server_host, server_port
    from Crypto.Hash import SHA256
    user_info = (ip, port)
    auth_coin = tx_with_sign['auth_coin']
    wallet.auth_coins[(ip, port)] = auth_coin
    user_pubkey = RSA.importKey(user_public_keys[(ip, port)])
    #search owner of C
    owner_public_key = json.loads(requests.get('http://{host}:{port}/coin_owner'.format(host=server_host, port=server_port), data=tx_with_sign['id'].encode()).text)
    if owner_public_key['public_key'] != user_public_keys[(ip, port)]: return False
    auth_coin_content = auth_coin['auth_coin']
    server_signature = auth_coin['signature']
    validate = server_public_key.verify(SHA256.new(auth_coin_content.encode()).digest(), server_signature)
    return validate


def generate_transaction(public_key, send=False):
    if send:
        transaction = {'coin_type': CoinType.AuthCoin,
            'trans_type': TransType.DISCONNECT,
            'sender': wallet.pub_file,
            'recipient': public_key,
            'amount': 1}
        return json.dumps(transaction)

    transaction = {'coin_type': CoinType.AuthCoin,
            'trans_type': TransType.CONNECT,
            'sender': public_key,
            'recipient': wallet.pub_file,
            'amount': 1}
    return json.dumps(transaction)


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
            response, diconnect = handle_data(data, self.ip, self.port)
            #print(response)
            if not response:
                continue
            if diconnect:
                print(response)
            conn.send(response.encode())

threads = []

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((host, socket_port))
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

