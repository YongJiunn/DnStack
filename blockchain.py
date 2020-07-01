"""
Block chain Implementation

Author @ Zhao Yea
"""

import hashlib
import json
from time import time


class Blockchain(object):
    def __init__(self):
        self.chain = []
        self.current_transactions = [{}]

        # Create the genesis block
        self.new_block(previous_hash=1, proof=100)

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """

        for transaction in self.current_transactions:
            block = {
                'index': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': transaction,
                'proof': proof,
                'previous_hash': previous_hash or self.block_hash(self.chain[-1]),
            }

            self.chain.append(block)

        # Reset the current list of transactions
        self.current_transactions = []

    def new_transaction(self, client, domain_name, zone_file_hash):
        """
        Creates a new chunk of data to go into the our Block chain
        @param client: <str> uuid of the requesting client
        @param domain_name: <str> Domain name
        @param zone_file_hash: <hash> Hash of zone file
        @return: <int> Index of the Block that will hold this transaction
        """

        self.current_transactions.append({
            'client': client,
            'domain_name': domain_name,
            'zone_file_hash': zone_file_hash
        })

        return self.last_block['index'] + 1

    def proof_of_work(self, previous_hash):
        """
        Simple Proof of Work Algorithm:
        :param previous_hash: <hash> Hash of the previous block
        :return: <int> Proof
        """

        proof = 0
        while not self.valid_proof(previous_hash, proof):
            proof += 1

        return proof

    def verify_blockchain(self, chain):
        """
        Verifies that the blockchain is authentic. Ensures equation is True.
        Equation: Previous hash * proof = 0000......
        @param chain: <list> Given Blockchain
        @return: Returns True if blockchain is verified, False otherwise
        """
        last_block = chain[1]
        current_index = 2

        while current_index < len(chain):
            block = chain[current_index]

            # Check the hash of the block is correct
            if block['previous_hash'] != self.block_hash(last_block):
                print("[!] Error in blockchain! Do not visit any domains until you can update your zone file")
                return False

            # Check that the Proof of Work is correct:
            if not self.valid_proof(last_block['previous_hash'], last_block['proof']):
                print("[!] Error in blockchain! Do not visit any domains until you can update your zone file")
                return False

            last_block = block
            current_index += 1

        print("[*] Blockchain verified successfully")
        return True

    def verify_block(self, block):
        """
        Verifies that the given Block is authentic
        @param block: <json> Given block
        @return: <bool>
        """
        if not self.valid_proof(block['previous_hash'], block['proof']):
            print("[!] Error in Block! Do not visit any domains until you can update your zone file")
            return False

        print("[*] Block verified successfully")
        return True

    @staticmethod
    def valid_proof(previous_hash, proof):
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param previous_hash: <int> Previous Hash of the block
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False if not.
        """
        # guess_hash = hashlib.sha256(f'{previous_hash * proof}'.encode()).hexdigest()
        # TODO This is a temp POW, faster for testing purposes
        guess_hash = hashlib.sha256(
            f'{previous_hash} * {proof}'.encode()).hexdigest()
        return guess_hash[:4] == "0000"

    @staticmethod
    def block_hash(block):
        """
        Create a SHA-256 hash of Block
        :param block: <dict> Block
        :return: <str> hash of block
        """

        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def generate_sha256(fname):
        """
        Generate a sha256 hash of the given file
        @param fname: <dir> Directory of the given filename
        @return: <hash> SHA256 Hash of the given file
        """

        file_hash = hashlib.sha256()
        with open(fname, "rb") as in_file:
            for chunk in iter(lambda: in_file.read(4096), b""):
                file_hash.update(chunk)

        return file_hash.hexdigest()

    @property
    def last_block(self):
        # Returns the last Block in the chain
        return self.chain[-1]
