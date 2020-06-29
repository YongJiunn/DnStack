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

# Public Key Directory
ALICE_PUBKEY_DIR = r"client/alice.pub"
BROKER_PUBKEY_DIR = r"client/dnStack.pub"

# Private Key Directory
ALICE_SECRET = r"C:\Users\STUDYFIRSTPLAYLATER\github\DnStack\secrets\alice_rsa"

# Directory to store Zone File
ZONE_FILE_DIR = r"client/{}/dns_zone.json".format(UUID)

# Databases
ZONE_DB_DIR = r"database/dns_zone.json"


class Client(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """

        # Initial pull request for updated zone file
        self.request_record(host, port)
        self.verify_blockchain()

        # Temporary menu system for Proof Of Concept (POC)
        # Client will be browser/proxy in the future
        while True:

            print(f"\n\t###### Today's Menu ######")
            # print(f"\t[1] Request for DNS record (Update)")
            print(f"\t[1] Register a new domain")
            print(f"\t[2] Resolve a domain")
            print(f"\t[3] Quit")

            user_option = input("\t >  ")

            if user_option == "3":
                # User wants to quit
                print("[!] Bye!")
                return
            elif user_option == "1":
                # !! Currently not working !!
                # User wants to register a new domain
                print("[!] Option to register new domain chosen")
                self.register_domain()
                return
            elif user_option == "2":
                # User wants to resolve a domain name
                print("[!] Option to resolve domain chosen")
                domain_name = input("[*] Enter domain name to resolve > ")
                self.resolve_domain(domain_name)
                return
            else:
                # User doesn't know what he wants
                print("[*] Please select an option.")

    def request_record(self, host, port):
        """
        Connects to the broker and requests for an update blockchain + zone file
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: Returns True if blockchain + zonefile was updated successfully, False otherwise
        """

        print(f"[*] Connecting to Broker @ ({host},{port})")

        # Start the blockchain
        self.blockchain = Blockchain()

        # Initialise socket
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connects to broker
        try:
            self.client_sock.connect((host, port))
        except ConnectionRefusedError:
            print(
                f"[!] Connection failed! Please check your network connectivity and try again.")
            return False

        # Send client pubkey over to server on initial connection
        server_hello_msg = (UUID, self.get_pubkey(ALICE_PUBKEY_DIR))
        self.client_sock.send(pickle.dumps(server_hello_msg))

        # Run the message_handle
        if self.message_handle():
            return True
        return False

    def register_domain(self):
        """
        Registers a new domain, currently only POC. Does not work fully.
        @return: True
        """

        # Requesting for new domain name to register
        print("[*] Please enter your new domain name, without any prefix. (Eg. google.stack, youtube.stack)")
        new_domain_name = input(" >  ")

        # Does a check if domain already exists
        print("[*] Checking if domain is taken... Please wait")
        with open(ZONE_FILE_DIR, "rb") as in_file:
            data = json.loads(in_file.read())

        for existing_domain in data.keys():
            if existing_domain == new_domain_name:
                print(
                    f"[*] Domain {new_domain_name} already exists! Please choose another domain.")
                return False

        # Defaults to fixed zone file
        print("\n[*] Please enter the path to your zone file. (Eg. C:\\Users\\bitcoinmaster\\bitcoinzone.json)")
        new_zone_file = input(" >  ")

        # [TODO] Check if zone_file
        #   1. Exists
        #   2. Is in correct json format
        new_zone_file = ZONE_DB_DIR

        print("\n\t###### Registering new domain ######")
        print(f"\tClient: {UUID}")
        print(f"\tDomain Name: {new_domain_name}")
        print(f"\tZone File: {new_zone_file}")

        user_confirmation = input("\n[*] Continue? Y/N > ")

        return True

    def resolve_domain(self, domain_name):
        """
        Resolves domains
        @param domain_name: <str> Domain name to resolve to IP address
        @return: Returns True if domain is resolved, False otherwise
        """

        # Loads in zone file
        with open(ZONE_FILE_DIR, "rb") as in_file:
            data = json.loads(in_file.read())

        # Loops through to locate requested domain
        for domains in data.keys():
            if domains == domain_name:
                print("\t###### IP Addresses ######")
                for i in data[domains]:
                    print(f"\t{i['type']}\t{i['data']}")
                return True
        print("[*] Domain does not exist! Have you updated your zone file?")
        return False


    def verify_blockchain(self):
        """
        Verifies that the blockchain is authentic. Ensures equation is True.
        Equation: Previous hash * proof = 0000......
        @return: Returns True if blockchain is verified, False otherwise
        """
        for i in self.blockchain.chain[1:]:
            proof = i["proof"]
            previous_hash = i["previous_hash"]
            if not Blockchain.valid_proof(previous_hash, proof):
                print("[!] Error in blockchain! Do not visit any domains until you can update your zone file")
                return False
        print("[*] Blockchain verified successfully")
        return True


    def message_handle(self):
        """
        Handles the message between server and client
        @return: Returns True if message is successfully received, False otherwise
        """

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
                    plaintext = rsa_cipher.decrypt_with_RSA(
                        privkey, ciphertext)
                    out_file.write(plaintext)
                print(f"[*] Zone File updated successfully")

            self.blockchain.chain = chain
            #print(json.dumps(self.blockchain.chain, indent=4))
            return True

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
