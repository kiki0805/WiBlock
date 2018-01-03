from time import time
from CONSTANTS import CoinType, TransType

################### BEGIN INDENTIFICATION #################

from secp256k1 import PrivateKey, PublicKey
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
from Crypto.Hash import SHA256
import base58
import uuid
import rsa
import json

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

class BlockChain(object):
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.create_block(previous_hash=1, proof=100)

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

from flask import Flask, request
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
    enc_auth_coin = public_key.encrypt(auth_coin_json.encode(), 32)

    signature = server_private_key.sign(SHA256.new(enc_auth_coin[0]).digest(), '')
    response_data = {'auth_coin': str(enc_auth_coin), 'signature': signature}
    json_data = json.dumps(response_data)

    blockchain.generate_transaction(coin_type=CoinType.AuthCoin,
            trans_type=TransType.ISSUE,
            sender=server_address,
            recipient=data['address'],
            amount=1)
    return json_data


@WiBlock.route('/transactions/generate', methods=['POST'])
def flask_generate_transaction():
    data = json.loads(request.data.decode())['raw']
    ##Todo checks required fields
    index = blockchain.generate_transaction(coin_type=data['coin_type'],
            trans_type=data['trans_type'],
            sender=data['sender'],
            recipient=data['recipient'],
            amount=data['amount'])
    #Todo broadcast TX
    response = {'message': 'Transaction generated successfully!'}
    return json.dumps(response)


@WiBlock.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return json.dumps(response)




class AuthCoin:
    def __init__(self, public_key, info):
        self.id = str(uuid.uuid4())
        self.public_key = public_key
        self.info = info


db.close()
WiBlock.run(host='0.0.0.0')


