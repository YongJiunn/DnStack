"""
Alice Prototype (Client)

Author @ Zhao Yea
"""

import os
import json
import pickle
import socket

from encryption.RSACipher import *
from blockchain import Blockchain

UUID = "4226355408"
HOST, PORT = "localhost", 1339
BUFSIZE = 1024
CACHE_SITES = []

# Flags
ZONE_FILE = "zone_file"
BLOCKCHAIN = "blockchain"

# Public Key Directory
ALICE_PUBKEY_DIR = r"client/alice.pub"
BROKER_PUBKEY_DIR = r"client/dnStack.pub"

# Private Key Directory
ALICE_SECRET = r"<put_ur_own_secret>"

# Directory to store Zone File
ZONE_FILE_DIR = r"client/{}/dns_zone.json".format(UUID)


class Client(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """
        # Start the blockchain
        self.blockchain = Blockchain()

        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_sock.connect((host, port))

        # Send client pubkey over to server on initial connection
        server_hello_msg = (UUID, self.get_pubkey(ALICE_PUBKEY_DIR))
        self.client_sock.send(pickle.dumps(server_hello_msg))

        # Run the message_handle
        self.message_handle()

    def message_handle(self):
        """ Handles the message between server and client """

        # Load the RSACipher for encryption/decryption
        rsa_cipher = RSACipher()
        privkey = rsa_cipher.load_privkey(ALICE_SECRET)

        try:
            # Prepare for incoming data
            data = b""
            while True:
                packet = self.client_sock.recv(BUFSIZE)

                if not packet:
                    break

                # Concatenate the data together
                data += packet

            # Load the encryption data list
            enc, chain = pickle.loads(data)

            # Prepare to write zone file contents locally and stored in client/ folder
            with open(ZONE_FILE_DIR, "wb") as out_file:
                for ciphertext in enc:
                    plaintext = rsa_cipher.decrypt_with_RSA(privkey, ciphertext)
                    out_file.write(plaintext)

            self.blockchain.chain = chain
            print(json.dumps(self.blockchain.chain, indent=4))

        except KeyboardInterrupt:
            self.client_sock.close()

        except socket.error:
            self.client_sock.close()

    @staticmethod
    def get_pubkey(pubkey_dir):
        """
        Function to get Public Key of Alice
        @param pubkey_dir: <str> Directory of the client's Public Key
        @return:
        """
        rsa_cipher = RSACipher()
        return rsa_cipher.load_pubkey(pubkey_dir).publickey().exportKey(format='PEM', passphrase=None, pkcs=1)


if __name__ == '__main__':
    # Create directory if it does not exist
    if not os.path.exists(os.path.dirname(ZONE_FILE_DIR)):
        os.mkdir(os.path.dirname(ZONE_FILE_DIR))

    # Run the client connection with the broker
    Client(HOST, PORT)
