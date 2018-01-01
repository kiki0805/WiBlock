from time import time
import json
import hashlib


class BlockChain(object):
    def __init__(self):
        self.chain = []
        self.current_transactions = []

    def create_block(self, proof):
        block = {
            'index': self.last_block['index'] + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': self.hash(self.last_block),
        }

        self.current_transactions = []
        self.chain.append(block)
        return block

    def generate_transaction(self, sender, recipient, amount):
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }

        self.current_transactions.append(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]
    
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


class AuthCoin:
    def issue(self):
        pass
