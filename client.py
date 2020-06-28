"""
Alice Prototype (Client)

Author @ Zhao Yea
"""

import pickle
import socket

from encryption.RSACipher import *
from blockchain import Blockchain

UUID = "4226355408"
HOST, PORT = "localhost", 1339
BUFSIZE = 4096
CACHE_SITES = []

# Public Key Directory
ALICE_PUBKEY_DIR = r"client/alice.pub"
BROKER_PUBKEY_DIR = r"client/dnStack.pub"


def get_pubkey(pubkey_dir):
    """
    Function to get Public Key of Alice
    @param pubkey_dir: <str> Directory of the client's Public Key
    @return:
    """
    rsa_cipher = RSACipher()
    return rsa_cipher.load_pubkey(pubkey_dir).publickey().exportKey(format='PEM', passphrase=None, pkcs=1)


class Client(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """
        # Start the blockchain
        # self.blockchain = Blockchain()

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


if __name__ == '__main__':
    broker = Client(HOST, PORT)
