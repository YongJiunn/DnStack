"""
Broker Script

Author @ Zhao Yea
"""

import json
import pickle
import socket
import hashlib
import threading
import socketserver
import pandas as pd
from functools import reduce

from encryption.RSACipher import *
from blockchain import Blockchain

# Server Settings
UUID = "Server"
HOST, PORT = "0.0.0.0", 1338
BUFSIZE = 2048

# Database
USER_DB_DIR = r"database/Users.txt"
DEFAULT_ZONE_DB = r"database/dns_zone.json"

# Admin
server_reply = "(Server)"
SECRET_KEY = r"secrets\dnStack_rsa"

# Server Flags
JOIN = "joined"
EXIT = "exit"
ZONE_FILE = "zone_file"
BLOCKCHAIN = "blockchain"
NEW_DOMAIN = "new_domain"
MINER = "miner"

# Server Actions
BROADCAST = "broadcast"
SELF_INFO = "self"

# Client Flags
REGIS_DOMAIN = "register_domain".encode()
MINER_PROOF = "miner".encode()

# client session
CLIENTS = {"Users": []}


class ThreadedServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        # Try catch the error
        try:
            # Get the user_id and public key
            user_id, user_pubkey = pickle.loads(self.request.recv(BUFSIZE))
            self.username = self.get_username(USER_DB_DIR, user_id)

            # Info message
            print(f"[*] {self.username} has started the connection.")

            # Add the new Client to the session DB
            CLIENTS["Users"].append({
                "id": self.request,
                "name": self.username,
                "pubkey": user_pubkey
            })

            if self.username == "miner":
                # Send previous hash to miner
                self.send_client(SELF_INFO, MINER)
            else:
                # Send Zone File to the client
                self.send_client(SELF_INFO, ZONE_FILE)

            # Run the message handler to receive client data
            self.message_handle()

        # Close the socket if client forcefully close the connection
        except socket.error:
            self.request.close()

    def send_client(self, action, flag):
        """
        Handles the sending feature to the respective clients that are connected to the Broker
        @param action: <str> Can be either to SELF or BROADCAST
        @param flag: <str> Requested flag to be performed
        @return: No return
        """
        # Load the RSA Cipher
        self.rsa_cipher = RSACipher()

        # Encryption list for temporary storage
        enc = []

        # Iterate through the CLIENTS session
        for session in CLIENTS["Users"]:
            client_sess = session['id']
            self.client_name = session['name']

            if self.client_name != "miner":
                client_pubkey = self.rsa_cipher.importRSAKey(session['pubkey'])

            # Peer to Peer communication with only one client
            if action == SELF_INFO and client_sess == self.request:
                # Send the zone file over to the client
                if flag == ZONE_FILE:
                    print(f"\t[+] Sending Zone file to {self.client_name}")

                    # Encrypt the Zone file with RSA Cipher
                    with open(DEFAULT_ZONE_DB, "rb") as in_file:
                        byte = in_file.read(1)
                        while byte != b"":
                            ciphertext = self.rsa_cipher.encrypt_with_RSA(
                                pub_key=client_pubkey, data=byte)
                            enc.append(ciphertext)
                            byte = in_file.read(1)

                    # Serialize the encrypted data and send to the client
                    msg = (enc, blockchain.chain)
                    client_sess.send(pickle.dumps(msg))

                    # Send Zone File flag to indicate EOL
                    client_sess.send(ZONE_FILE.encode())

                    # Reset the encryption list
                    enc = []
                elif flag == MINER:
                    print("[*] Sending hash to miner")
                    # Gets the last block hash
                    last_block_hash = (
                        blockchain.block_hash(blockchain.chain[-1]))

                    # Sends last block hash to miner
                    client_sess.send(last_block_hash.encode())

                    # Sends Miner flag to indicate EOL
                    client_sess.send(MINER.encode())

            # Communication to everyone except the requested client request
            elif action == BROADCAST and client_sess != self.request and self.client_name != "miner":
                # Send message the encrypted domain over to the client
                if flag == NEW_DOMAIN:
                    encrypted_domain = self.rsa_cipher.encrypt_with_RSA(
                        pub_key=client_pubkey, data=self.plain_domain)
                    print(
                        f"\t[+] Forwarding Domain information to: {self.client_name}")
                    client_sess.send(encrypted_domain)
                    client_sess.send(NEW_DOMAIN.encode())

    def message_handle(self):
        """ Handles the message between the broker and the client """
        if self.client_name != "miner":
            broker_privkey = self.rsa_cipher.load_privkey(SECRET_KEY)

        try:
            data = b""
            while True:
                # Receive Client send message
                packet = self.request.recv(BUFSIZE)
                if not packet:
                    # self.delete_client()
                    break

                # Register Domain Flag
                elif REGIS_DOMAIN in packet:
                    data += packet.rstrip(REGIS_DOMAIN)
                    # Load the encryption data list
                    enc, client_transaction = pickle.loads(data)

                    # Initialise client transaction to broker own transaction
                    blockchain.current_transactions.append(client_transaction)

                    print(
                        f"[*] {self.client_name} has registered for a domain")
                    # Decrypt the given encryption list
                    plaintext = [self.rsa_cipher.decrypt_with_RSA(broker_privkey, ciphertext) for ciphertext in
                                 enc]
                    self.plain_domain = b"".join(plaintext)
                    self.send_client(BROADCAST, NEW_DOMAIN)

                    # Resetting the data buffer
                    data, packet = b"", b""

                elif MINER_PROOF in packet:
                    data += packet.rstrip(MINER_PROOF)
                    proof, prev_hash = pickle.loads(data)

                    if blockchain.valid_proof(prev_hash, proof):
                        print(
                            f"[*] Proof verified, creating new block {self.client_name}")

                        if len(blockchain.current_transactions) == 0:
                            # Creates bogus transaction
                            blockchain.new_transaction(
                                client="3234739665", domain_name="miner.stack", zone_file_hash=hashlib.sha256(b"miner").hexdigest())

                        # Creates new block
                        blockchain.new_block(
                            proof=proof, previous_hash=prev_hash)

                        self.send_client(SELF_INFO, MINER)

                    # Resetting the data buffer
                    data, packet = b"", b""

                # Concatenate the data together
                data += packet

        except socket.error:
            self.delete_client()
            self.request.close()

    def delete_client(self):
        # Delete the client in the dictionary list
        for index in range(len(CLIENTS["Users"])):
            if CLIENTS["Users"][index]["id"] == self.request:
                del CLIENTS["Users"][index]

        print(f"[*] {self.username} left the chat room.")

    @staticmethod
    def get_username(user_db, user_id):
        user_df = pd.read_csv(user_db, sep=",", header=0)
        # Check whether the user_id exist in the ID column of dataframe
        if user_id in map(lambda x: str(x), user_df.id.values):
            return user_df.loc[user_df.id.isin([user_id])].name.to_string(index=False).lstrip()

    @staticmethod
    def construct_block():
        return


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def construct_blockchain(bc):
    """ Construct the Blockchain from the Zone File """
    # Open the Zone File and load it
    with open(DEFAULT_ZONE_DB, "rb") as in_file:
        data = json.loads(in_file.read())

    for domain_name in data.keys():
        bc.new_transaction(client=UUID,
                           domain_name=domain_name,
                           zone_file_hash=bc.generate_sha256(DEFAULT_ZONE_DB))

        # Does Proof of Work
        last_block = bc.last_block
        previous_hash = bc.block_hash(last_block)
        proof = bc.proof_of_work(previous_hash)

        # Create the new block
        bc.new_block(proof=proof, previous_hash=previous_hash)


if __name__ == "__main__":
    # Start and construct the Blockchain
    blockchain = Blockchain()
    print("[*] Constructing Blockchain ...")
    construct_blockchain(blockchain)
    print("\t[+] Blockchain constructed !!!")

    # Start the Broker Server
    server = ThreadedServer((HOST, PORT), ThreadedServerHandle)
    print(f"[*] Server Started on {HOST}:{PORT}")
    # Start the server thread to thread every single client
    server_thread = threading.Thread(target=server.serve_forever())
    server_thread.start()
