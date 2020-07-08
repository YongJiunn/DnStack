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
import hashlib
import logging

from encryption.RSACipher import *
from blockchain import Blockchain

# Server Settings
UUID = "Server"
HOST, PORT = "0.0.0.0", 1335
BUFSIZE = 1024

# Database
USER_DB_DIR = r"database/Users.txt"
ZONE_DB_DIR = r"database/dns_zone.json"

# Admin
server_reply = "Server"
SECRET_KEY = r"secrets/dnStack_rsa"

# Server Flags
ZONE_FILE = "test_zone_file".encode()
BLOCKCHAIN = "blockchain".encode()
NEW_DOMAIN = "new_domain".encode()
MINER = "miner".encode()

# Client Flags
REGIS_DOMAIN = "register_domain".encode()
MINER_PROOF = "miner".encode()
CONSENSUS = "consensus".encode()

# Admin Site Log Files
SYSLOG = r"logs/sysinfo.log"
CLIENT_SESS_LOG = r"logs/client_session.log"
DOMAIN_PROFILES_LOG = r"logs/domain_profiles.log"
BLOCKCHAIN_LOG = r"logs/blockchain.log"

# client session
CLIENT_DF = pd.DataFrame(columns=["id", "client_name", "pubkey"])

# Logging Feature
logging.basicConfig(level=logging.INFO,
                    format="%(created)f [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(SYSLOG, "w+"), logging.StreamHandler()]
                    )


class ThreadedServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        global CLIENT_DF

        # Try catch the error
        try:
            # Get the user_id and public key
            user_id, user_pubkey = pickle.loads(self.request.recv(BUFSIZE))
            self.username = self.get_username(USER_DB_DIR, user_id)

            # Info message
            logging.info(f"{self.username} has started the connection.")

            # Add the new Client to the session DB
            CLIENT_DF = CLIENT_DF.append({
                "id": self.request,
                "client_name": self.username,
                "pubkey": user_pubkey
            }, ignore_index=True)

            # Write Active Clients to Log File
            with open(CLIENT_SESS_LOG, "w+") as out_file:
                out_file.write(CLIENT_DF['client_name'].str.cat(sep=','))

            # Check for the logon username
            if self.username == "miner":
                # Send previous hash to miner
                self.send_miner()
            else:
                # Send Zone File to the client
                self.send_client(ZONE_FILE)

            # Run the message handler to receive client data
            self.message_handle()

        # Close the socket if client forcefully close the connection
        except socket.error:
            self.request.close()

    def send_client(self, flag):
        """
        Handles the sending feature to the respective clients that are connected to the Broker        
        @param flag: <str> Requested flag to be performed
        @return: No return
        """
        # Load the RSA Cipher
        self.rsa_cipher = RSACipher()

        # Encryption list for temporary storage
        enc = []

        recipient_df = CLIENT_DF.loc[CLIENT_DF['id'] == self.request]
        client_sess, client_name, pubkey = recipient_df.values[0]
        client_pubkey = self.rsa_cipher.importRSAKey(pubkey)

        if flag == ZONE_FILE:
            logging.info(f"Sending Zone file to {client_name}")
            # Open and read the zone file bye by byte
            with open(ZONE_DB_DIR, "rb") as in_file:
                while (byte := in_file.read(1)):
                    # Encrypt the Zone file with RSA Cipher
                    ciphertext = self.rsa_cipher.encrypt_with_RSA(pub_key=client_pubkey, data=byte)
                    enc.append(ciphertext)

            # Serialize the encrypted data and send to the client
            msg = (enc, blockchain.chain)
            client_sess.sendall(pickle.dumps(msg))

            # Send Zone File flag to indicate EOL
            client_sess.sendall(ZONE_FILE)

            # Reset the encryption list
            enc = []

        elif flag == CONSENSUS:
            logging.info(f"Client {client_name} request for Consensus")

            # Send the Block Chain to Client
            client_sess.sendall(pickle.dumps(blockchain.chain))
            # Send CONSENSUS flag to indicate EOL
            client_sess.sendall(CONSENSUS)

        elif flag == NEW_DOMAIN:
            recipient_df = CLIENT_DF.loc[
                (CLIENT_DF['id'] != self.request) & (CLIENT_DF['client_name'] != MINER.decode())]

            if not recipient_df.empty:
                for items in recipient_df[['id', 'pubkey']].values:
                    # Import the Public Key
                    client_sess = items[0]
                    client_pubkey = self.rsa_cipher.importRSAKey(items[1])

                    encrypted_domain = self.rsa_cipher.encrypt_with_RSA(pub_key=client_pubkey, data=self.plain_domain)

                    logging.info(f"Forwarding Domain information to all nodes")
                    client_sess.sendall(encrypted_domain)
                    client_sess.sendall(NEW_DOMAIN)

    def send_miner(self):
        """ Function that sends message to MINERS """
        recipient_df = CLIENT_DF.loc[CLIENT_DF['id'] == self.request]
        miner_sess = recipient_df['id'].values[0]

        logging.info("Sending hash to miner")
        # Gets the last block hash
        last_block_hash = (blockchain.block_hash(blockchain.chain[-1]))
        # Sends last block hash to miner
        miner_sess.sendall(last_block_hash.encode())
        # Sends Miner flag to indicate EOL
        miner_sess.sendall(MINER)

    def message_handle(self):
        """ Handles the message between the broker and the client """
        if self.username != MINER.decode():
            broker_privkey = self.rsa_cipher.load_privkey(SECRET_KEY)

        try:
            data = b""
            while True:
                # Receive Client send message
                packet = self.request.recv(BUFSIZE).strip()

                if not packet:
                    self.delete_client()
                    break

                # Register Domain Flag
                elif REGIS_DOMAIN in packet:
                    data += packet.rstrip(REGIS_DOMAIN)
                    # Load the encryption data list
                    enc, client_transaction = pickle.loads(data)

                    # Resetting the data buffer
                    data, packet = b"", b""

                    # Initialise client transaction to broker own transaction
                    blockchain.current_transactions.append(client_transaction[0])

                    logging.info(f"{self.username} has registered for a domain")
                    # Decrypt the given encryption list
                    plaintext = [self.rsa_cipher.decrypt_with_RSA(broker_privkey, ciphertext) for ciphertext in enc]
                    self.plain_domain = b"".join(plaintext)

                    # Save the Domain Registration Information
                    with open(DOMAIN_PROFILES_LOG, "a+") as out_file:
                        out_file.write(f"{self.username}::{self.plain_domain.decode()}\n")

                    self.send_client(NEW_DOMAIN)

                # MINER HANDLER
                elif MINER in packet:
                    data += packet.rstrip(MINER)
                    proof, prev_hash = pickle.loads(data)

                    # Resetting the data buffer
                    data, packet = b"", b""

                    if blockchain.valid_proof(prev_hash, proof):
                        logging.info(f"Proof verified, creating new block ...")

                        if len(blockchain.current_transactions) == 0:
                            # Creates bogus transaction
                            blockchain.new_transaction(client="3234739665",
                                                       domain_name="miner.stack",
                                                       zone_file_hash=hashlib.sha256(b"miner").hexdigest())

                        # Creates new block
                        blockchain.new_block(proof=proof, previous_hash=prev_hash)

                        # Save the Current Blockchain to a log file
                        with open(BLOCKCHAIN_LOG, "w+") as out_file:
                            out_file.write(json.dumps(blockchain.chain))

                        # Send the next hash to MINER
                        self.send_miner()

                # Consensus Handler
                elif CONSENSUS in packet:
                    # Resetting the data buffer
                    data, packet = b"", b""
                    # Sends updated Blockchain to client
                    self.send_client(CONSENSUS)

                # Concatenate the data together
                data += packet

        except socket.error:
            self.delete_client()
            self.request.close()

    def delete_client(self):
        # Delete the client in the dictionary list
        CLIENT_DF.drop(CLIENT_DF.loc[CLIENT_DF['id'] == self.request].index, inplace=True)
        self.request.close()
        logging.info(f"{self.username} has been disconnected.")

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

    # Save the Current Blockchain to a log file
    with open(BLOCKCHAIN_LOG, "w+") as out_file:
        out_file.write(json.dumps(blockchain.chain))


if __name__ == "__main__":
    # Start and construct the Blockchain
    blockchain = Blockchain()
    logging.info("Constructing Blockchain ...")
    construct_blockchain(blockchain)
    logging.info("Blockchain constructed !!!")

    # Empty the New Domain Log Files
    open(DOMAIN_PROFILES_LOG, 'w').close()
    open(CLIENT_SESS_LOG, 'w').close()

    # Start the Broker Server
    server = ThreadedServer((HOST, PORT), ThreadedServerHandle)

    try:
        with server:
            logging.info(f"Server Started on {HOST}:{PORT}")

            # Start the server thread to thread every single client
            server_thread = threading.Thread(target=server.serve_forever())
            server_thread.daemon = True
            server_thread.start()
            server.shutdown()

    except KeyboardInterrupt:
        logging.info("Shutting down Broker ...")
        server.shutdown()
