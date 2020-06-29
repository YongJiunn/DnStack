"""
Broker Script

Author @ Zhao Yea 
"""

import json
import pickle
import socket
import threading
import socketserver
import pandas as pd
import progressbar

from encryption.RSACipher import *
from blockchain import Blockchain

# Server Settings
UUID = "(Server)"
HOST, PORT = "0.0.0.0", 1339
BUFSIZE = 2048

# Database
USER_DB_DIR = r"database/Users.txt"
ZONE_DB_DIR = r"database/dns_zone.json"

# Admin
server_reply = "(Server)"

# FLAGS
JOIN = "joined"
EXIT = "exit"
ZONE_FILE = "zone_file"
BLOCKCHAIN = "blockchain"

# client session
CLIENTS = {"Users": []}


class ThreadedServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        # Try catch the error
        try:
            # Get the user_id and public key
            user_id, self.user_pubkey = pickle.loads(self.request.recv(BUFSIZE))
            self.username = self.get_username(USER_DB_DIR, user_id)

            # Info message
            print(f"[*] {self.username} has started the connection.")

            # Add the client session
            CLIENTS["Users"].append({
                "id": self.request,
                "name": self.username
            })

            # Send Zone File to the client
            self.send_client(ZONE_FILE)

            # Run the message handler to receive client data
            self.message_handle()

        # Close the socket if client forcefully close the connection
        except socket.error:
            self.delete_client()
            self.request.close()

    def send_client(self, flag):
        # Load the RSA Cipher
        rsa_cipher = RSACipher()
        client_pubkey = rsa_cipher.importRSAKey(self.user_pubkey)
        # Encryption list for temporary storage
        enc = []

        for session in CLIENTS["Users"]:
            client_sess = session['id']
            client_name = session['name']

            if client_sess == self.request:
                # Send the zone file over to the client
                if flag == "zone_file":
                    # Encrypt the Zone file with RSA Cipher
                    with open(ZONE_DB_DIR, "rb") as in_file:
                        for line in in_file:
                            ciphertext = rsa_cipher.encrypt_with_RSA(pub_key=client_pubkey, data=line.strip())
                            enc.append(ciphertext)

                    # Serialize the encrypted data and send to the client
                    msg = (enc, blockchain.chain)
                    client_sess.send(pickle.dumps(msg))

                    # Send Zone File flag to indicate EOL
                    client_sess.send(ZONE_FILE.encode())

                    # Reset the encryption list
                    enc = []

    def message_handle(self):
        try:
            while True:
                # Receive Client send message
                self.data = self.request.recv(BUFSIZE)

                if not self.data:
                    self.delete_client()
                    break

                print(self.data)

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


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def construct_blockchain(bc):
    """ Construct the Blockchain from the Zone File """
    # Open the Zone File and load it
    with open(ZONE_DB_DIR, "rb") as in_file:
        data = json.loads(in_file.read())

    for domain_name in data.keys():
        bc.new_transaction(client=UUID,
                           domain_name=domain_name,
                           zone_file_hash=bc.generate_sha256(ZONE_DB_DIR))

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
    print("[+] Blockchain constructed !!!")

    # Start the Broker Server
    server = ThreadedServer((HOST, PORT), ThreadedServerHandle)
    print(f"[*] Server Started on {HOST}:{PORT}")
    # Start the server thread to thread every single client
    server_thread = threading.Thread(target=server.serve_forever())
    server_thread.start()
