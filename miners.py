"""
Miner Script

Author @ Zhao Yea
"""

import time
import socket
import pickle
import hashlib

UUID = "3234739665"
HOST, PORT = "localhost", 1335
BUFSIZE = 2048
MINER = "miner".encode()


class Miners(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """

        # Initial pull request for updated zone file
        self.request_hash(host, port)

        self.message_handle()

    def request_hash(self, host, port):
        """
        Initiate Connection to Broker
        @param host: IP address of Broker
        @param port: Port of Broker
        @return: NIL
        """

        print(f"[*] Connecting to Broker @ ({host},{port})")

        # Initialise socket
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connects to broker
        try:
            self.client_sock.connect((host, port))
        except ConnectionRefusedError:
            print(f"[!] Connection failed! Please check your network connectivity and try again.")
            return False

        # Send client pubkey over to server on initial connection
        server_hello_msg = (UUID, "")
        self.client_sock.send(pickle.dumps(server_hello_msg))

    def message_handle(self):
        """ Handles the message between the broker and the client """

        data = b""
        while True:
            # Receive Client send message
            packet = self.client_sock.recv(BUFSIZE)

            if not packet:
                # break
                pass

            elif MINER in packet:
                data += packet.rstrip(MINER)
                prev_hash = data.decode()
                data, packet = b"", b""

                # Start mining for proof
                proof = str(self.proof_of_work(prev_hash))
                time.sleep(15)
                print(f"[*] Proof found for hash {prev_hash}, {proof}")

                # Sends proof and previous hash to broker
                self.client_sock.send(pickle.dumps((proof, prev_hash)))

                self.client_sock.send(MINER)

            # Concatenate the data together
            data += packet

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

    def valid_proof(self, previous_hash, proof):
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param previous_hash: <int> Previous Hash of the block
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False if not.
        """
        # guess_hash = hashlib.sha256(f'{previous_hash * proof}'.encode()).hexdigest()
        # TODO This is a temp POW, faster for testing purposes
        guess_hash = hashlib.sha256(f'{previous_hash} * {proof}'.encode()).hexdigest()
        return guess_hash[:4] == "0000"


if __name__ == "__main__":
    miner = Miners(HOST, PORT)
