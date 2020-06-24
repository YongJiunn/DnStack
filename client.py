"""
Alice Prototype (Client)

Author @ Zhao Yea
"""

import pickle
import socket
import json
import hashlib

from encryption.RSACipher import *

UUID = "4226355408"
HOST, PORT = "localhost", 1337
BUFSIZE = 2048
CACHE_SITES = []

# Public Key Directory
ALICE_PUBKEY_DIR = r"client/alice.pub"
BROKER_PUBKEY_DIR = r"client/dnStack.pub"


def get_pubkey(pubkey_dir):
    """ Function to get Public Key of Alice """
    rsa_cipher = RSACipher()
    return rsa_cipher.load_pubkey(ALICE_PUBKEY_DIR).publickey().exportKey(format='PEM', passphrase=None, pkcs=1)


class Broker(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        :param host: <str> IP Addr of the Broker
        :param port: <int> Port number of the Broker
        :param return: <sock> Client socket connection to the Broker
        """

        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_sock.connect((host, port))

        # Send client pubkey over to server on initial connection
        server_hello_msg = (UUID, get_pubkey(ALICE_PUBKEY_DIR))
        self.client_sock.send(pickle.dumps(server_hello_msg))

        # Run the message_handle
        self.message_handle()

    def message_handle(self):
        """ Handles the message between server and client """
        try:
            while True:
                data = self.client_sock.recv(BUFSIZE).decode()

                if not data:
                    break

                print(data)


        except KeyboardInterrupt:
            self.client_sock.close()

        except socket.error:
            self.client_sock.close()


# TODO <Jon to implement this part>
# class ClientBlockChain(object):
#     def __init__(self, recipient, sender):
#         """
#         Create Blockchain with initial genesis block given recipient and sender
#         :param recipient: <str> UUID of recipient
#         :param sender: <str> UUID of client which is launching program
#         """
#         self.chain = []
#
#         # Create Genesis Block
#         self.new_block(recipient, sender, previous_hash=1)
#
#     def new_block(self, recipient, sender, key=None, data=None, previous_hash=None, eol=0):
#         """
#         Creation of block given users, key and data
#         :param recipient: <str> UUID of recipient
#         :param sender: <str> UUID of client which is launching program
#         :param key: (Optional) <str> Public key of recipient
#         :param data: (Optional) <str> Plaintext bytes
#         :param previous_hash: (Optional) <str> Hash of previous Block
#         :param eol: (Optional) <int> Indicates end of block
#         :return:
#         """
#         block = {
#             'timestamp': int(time()),
#             'transactions': [
#                 {
#                     'key': key,
#                     'data': str(pickle.dumps((eol, data))),
#                     'recipient': recipient,
#                     'sender': sender
#                 }
#             ],
#             'previous_hash': previous_hash or self.hash(self.last_block),
#             'next_hash': 1
#         }
#         self.chain.append(block)
#
#         return block
#
#     def get_chain(self):
#         # Get json of the current chain
#         data_object = {
#             'chain': self.chain,
#             'length': self.chain_length
#         }
#         # Return chain
#         return json.dumps(data_object, indent=4)
#
#     def next_hash_prev_block(self):
#         # Returns next_hash of previous block
#         return self.last_block["next_hash"]
#
#     def __str__(self):
#         return self.get_chain()
#
#     @staticmethod
#     def hash(block):
#         """
#         Create a SHA-256 hash of Block
#         :param block: <dict> Block
#         :return: <str> hash of block
#         """
#
#         block_string = json.dumps(block, sort_keys=True).encode()
#         return hashlib.sha256(block_string).hexdigest()
#
#     @property
#     def last_block(self):
#         # Returns the last Block in the chain
#         return self.chain[-1]
#
#     @property
#     def chain_length(self):
#         # Returns length of chain
#         return len(self.chain)


if __name__ == '__main__':
    broker = Broker(HOST, PORT)
