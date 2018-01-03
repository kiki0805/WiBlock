from time import time

################ options setting ##########################

import sys, getopt, os
from get_host_ip import get_host_ip
from validate_port import validate_port

opts, args = getopt.getopt(sys.argv[1:], 'hp:')
host = get_host_ip()

port = None
for op, value in opts:
    if op == '-p':
        port = eval(value)
    elif op == '-h':
        print('Usage:\n\tpython server.py -p CustomizedPort')
        sys.exit()
    else:
        print('Unknown parameter(s).')
        sys.exit()

if not port:
    print('Please set port. Use -h for help.')
    sys.exit()


if not validate_port(port):
    print('Connection refused. Port {} may be occupied. Try to choose another one.'.format(str(port)))
    sys.exit()


print('Running node at ' + host + ':' + str(port) + '...')


######################### options setting ##########################


from CONSTANTS import CoinType, TransType

################### BEGIN INDENTIFICATION #################

from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
from Crypto.Hash import SHA256
import uuid
import json
import requests

files = os.listdir(os.getcwd())
if 'SERVER_PUBLIC' not in files or 'SERVER_PRIVATE' not in files or 'SERVER_ADDRESS' not in files:
    os.system('python server_generator.py')


server_public_key = None
with open('SERVER_PUBLIC', 'r') as f:
    server_pub_file = f.read()
    server_public_key = RSA.importKey(server_pub_file)
    f.close()

server_private_key = None
with open('SERVER_PRIVATE', 'r') as f:
    server_priv_file = f.read()
    server_private_key = RSA.importKey(server_priv_file)
    f.close()

server_address = None
with open('SERVER_ADDRESS', 'r') as f:
    server_address = f.read()
    f.close()


################## END IDENTIFICATION #########################

from urllib.parse import urlparse

class BlockChain(object):
    def __init__(self):
        self.chain = []
        self.nodes = set()
        self.current_transactions = []
        self.create_block(previous_hash=1, proof=100)

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        for i in range(len(chain) - 1):
            former_block = chain[i]
            current_block = chain[i + 1]

            if current_block['previous_hash'] != self.hash(former_block):
                return False

            if not self.valid_proof(current_block['proof'], former_block['proof']):
                return False

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://{node}/chain'.format(node=node))

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def create_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.last_block),
        }

        self.current_transactions = []
        self.chain.append(block)
        return block

    def generate_transaction(self, coin_type, trans_type, sender, recipient, amount):
        transaction = {
            'coin_type': coin_type,
            'trans_type': trans_type,
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }

        self.current_transactions.append(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        try:
            return self.chain[-1]
        except:
            return None
    
    @staticmethod
    def hash(block):
        if not block:
            return None
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(proof, last_proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(proof, last_proof):
        guess = '{last_proof}{proof}'.format(last_proof=last_proof, proof=proof).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == '0000'


from flask import Flask, request, jsonify
from peewee import *
from playhouse.shortcuts import model_to_dict

WiBlock = Flask(__name__)

db = SqliteDatabase('WiBlock.db')

class Registration(Model):
    info = TextField()
    public_key = TextField()
    asset_id = CharField()

    class Meta:
        database = db

db.connect()
#db.create_tables([Registration])


blockchain = BlockChain()


@WiBlock.route('/register4AP', methods=['POST'])
def register4AP():
    enc_data = request.data
    json_data = json.loads(enc_data.decode())
    data = b''
    for i in range(len(json_data)):
        data += server_private_key.decrypt(eval(json_data[str(i)]))
    data += b'}'
    data = json.loads(data.decode())
    registration = Registration(info=data['info'], public_key=data['public_key'], asset_id='')
    registration.save()
    
    response = {'success_message': 'Register Successfully!'}
    return json.dumps(response)



@WiBlock.route('/register', methods=['POST'])
def register():
    enc_data = request.data
    json_data = json.loads(enc_data.decode())
    data = b''
    for i in range(len(json_data)):
        data += server_private_key.decrypt(eval(json_data[str(i)]))
    data += b'}'
    data = json.loads(data.decode())
    auth_coin = AuthCoin(public_key=data['public_key'], info=data['info'])
    registration = Registration(info=auth_coin.info, public_key=auth_coin.public_key, asset_id=auth_coin.id)
    registration.save()

    auth_coin_dic = auth_coin.__dict__
    auth_coin_json = json.dumps(auth_coin_dic)

    public_key = RSA.importKey(data['public_key'])
    auth_coin_encoded = auth_coin_json.encode()
    length = len(auth_coin_encoded)
    enc_auth_coin = {}
    import math
    for i in range(math.ceil(length / 128)):
        start = i * 128
        end = start + 128
        if end >= length:
            end = -1
        enc_auth_coin[i] = str(public_key.encrypt(auth_coin_encoded[start: end], 32)[0])

    signature = server_private_key.sign(SHA256.new(json.dumps(enc_auth_coin).encode()).digest(), '')
    response_data = {'auth_coin': json.dumps(enc_auth_coin), 'signature': signature}
    json_data = json.dumps(response_data)

    blockchain.generate_transaction(coin_type=CoinType.AuthCoin,
            trans_type=TransType.ISSUE,
            sender=server_public_key.exportKey().decode(),
            recipient=data['public_key'],
            amount=1)
    return json_data


@WiBlock.route('/transactions/generate', methods=['POST'])
def flask_generate_transaction():
    data = json.loads(request.data.decode())
    signature = data['signature']
    data = data['raw']
    public_key = RSA.importKey(data['sender'])
    if not public_key.verify(SHA256.new(json.dumps(data).encode()).digest(), signature):
        response = {'fail_message': 'Invalid Transaction.'}
        return json.dumps(response), 400

    ##Todo checks required fields
    index = blockchain.generate_transaction(coin_type=data['coin_type'],
            trans_type=data['trans_type'],
            sender=data['sender'],
            recipient=data['recipient'],
            amount=data['amount'])
    #Todo broadcast TX
    response = {'success_message': 'Transaction generated successfully!'}
    return json.dumps(response)


@WiBlock.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return json.dumps(response)


@WiBlock.route('/coin_owner', methods=['GET'])
def get_coin_owner():
    asset_id = request.data.decode()
    registration = Registration.get(Registration.asset_id == asset_id)
    public_key = registration.public_key
    response = {'public_key': public_key}
    return json.dumps(response)


@WiBlock.route('/transactions/current', methods=['GET'])
def get_current_transactions():
    response = {
        'current_transactions': blockchain.current_transactions,        
    }
    return json.dumps(response)


@WiBlock.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.generate_transaction(
        coin_type=CoinType.RewardCoin,
        trans_type=TransType.ISSUE,
        sender='0',
        recipient=server_public_key.exportKey().decode(),
        amount=1,
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(proof, previous_hash)

    response = {
        'message': "New Block Created",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash']
    }

    return json.dumps(response)

@WiBlock.route('/nodes/register', methods=['POST'])
def register_nodes():
    nodes = json.loads(request.data.decode())['nodes']
    if nodes is None:
        return 'Invalid list of nodes', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nondes have been added',
        'total_nodes': list(blockchain.nodes),
    }

    return json.dumps(response)

@WiBlock.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Replaced',
            'new_chain': blockchain.chain,
        }
    else:
        response = {
            'message': 'Authoritative',
            'chain': blockchain.chain,
        }

    return json.dumps(response)
class AuthCoin:
    def __init__(self, public_key, info):
        self.id = str(uuid.uuid4())
        self.public_key = public_key
        self.info = info


db.close()
WiBlock.run(host=host, port=port)


