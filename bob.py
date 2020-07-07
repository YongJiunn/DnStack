"""
Alice Prototype (Client)

Author @ Zhao Yea && Gerald Peh
"""

import os
import json
import pickle
import socket
import random
import struct
import threading
import pandas as pd

from encryption.RSACipher import *
from blockchain import Blockchain

UUID = "2112200367"
HOST, PORT = "localhost", 1335
BUFSIZE = 4096

# Public Key Directory
CLIENT_PUBKEY_DIR = r"client/bob.pub"
BROKER_PUBKEY_DIR = r"client/dnStack.pub"

# Private Key Directory
SECRET_KEY = r"secrets/bob_rsa"

# Directory to store Zone File
DEFAULT_ZONE_FILE = r"client/{}/dns_zone.json".format(UUID)
ZONE_FILE_DIR = r"client/{}".format(UUID)

# Server Flags
ZONE_FILE = "test_zone_file".encode()
NEW_DOMAIN = "new_domain".encode()

# Client Flags
REGIS_DOMAIN = "register_domain".encode()
CONSENSUS = "consensus".encode()

# Cache Sites DataFrame
CACHE_SITES = pd.DataFrame(columns=["domain_name", "ip", "type"])


class Client(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """        
        print(f"[*] Connecting to Broker @ ({host},{port})")

        # Start the blockchain
        self.blockchain = Blockchain()

        # Initialise socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.client_sock = sock

            # Connects to broker
            try:
                self.client_sock.connect((host, port))

            except socket.error:
                print("[!] Connection failed! Please check your network connectivity and try again.")
                self.client_sock.close()

            # Send client pubkey over to server on initial connection
            server_hello_msg = (UUID, self.get_pubkey(CLIENT_PUBKEY_DIR))
            self.client_sock.sendall(pickle.dumps(server_hello_msg))

            # Run the message_handle
            self.message_handle()

    def message_handle(self):
        """ Handles the message between server and client """

        # Load the RSACipher for encryption/decryption
        self.rsa_cipher = RSACipher()
        privkey = self.rsa_cipher.load_privkey(SECRET_KEY)

        try:
            # Prepare for incoming data
            data = b""
            while True:
                packet = self.client_sock.recv(BUFSIZE)

                # Break out of the loop the connection is lost to the server
                if not packet:
                    break

                elif CONSENSUS in packet:
                    # Strip the flag
                    data += packet.rstrip(CONSENSUS)

                    # Load the encrypted data list
                    chain = pickle.loads(data)

                    # Reset the data buffer
                    data, packet = b"", b""
                    
                    # Verify the given blockchain
                    if self.blockchain.verify_blockchain(chain):
                        # Update the client Blockchain
                        self.blockchain.chain = chain

                # ZONE FILE HANDLER
                elif ZONE_FILE in packet:
                    # Strip the flag
                    data += packet.rstrip(ZONE_FILE)

                    # Load the encrypted data list
                    enc, chain = pickle.loads(data)

                    # Reset the data buffer
                    data, packet = b"", b""

                    # Prepare to write zone file contents locally and stored in client/ folder
                    print(f"[+] Zone file received from Broker, saving under: {DEFAULT_ZONE_FILE}")
                    with open(DEFAULT_ZONE_FILE, "wb") as out_file:
                        for ciphertext in enc:
                            plaintext = self.rsa_cipher.decrypt_with_RSA(privkey, ciphertext)
                            out_file.write(plaintext)

                    # Verify the given blockchain
                    if self.blockchain.verify_blockchain(chain):
                        # Update the client Blockchain
                        self.blockchain.chain = chain

                        # Run the user_menu
                        threading.Thread(target=self.user_menu).start()
                    

                # NEW DOMAIN File Handler
                elif NEW_DOMAIN in packet:
                    print("[+] Receiving a new domain zone file")
                    # Strip the flag
                    data += packet.rstrip(NEW_DOMAIN)
                    # Load the encrypted data into a dictionary
                    new_domain = json.loads(self.rsa_cipher.decrypt_with_RSA(priv_key=privkey, data=data))

                    # Reset the data buffer
                    data, packet = b"", b""

                    # Extract the domain_name
                    domain_name = list(new_domain.keys())[0]
                    new_domain_zone_fpath = f"client/{UUID}/{domain_name}.json"

                    print(f"[+] Writing new zone file: {domain_name} to {new_domain_zone_fpath}")
                    # Save the new domain zone file locally
                    with open(new_domain_zone_fpath, "w") as out_file:
                        out_file.write(json.dumps(new_domain))


                # Concatenate the data
                data += packet

        except KeyboardInterrupt:
            self.client_sock.close()

        except socket.error:
            self.client_sock.close()

    def send_server(self, flag):
        """ Constructs and forward data over to the broker """
        pubkey = self.rsa_cipher.load_pubkey(BROKER_PUBKEY_DIR)
        enc = []

        if flag == REGIS_DOMAIN:
            with open(self.new_zone_fpath, "rb") as in_file:
                while (byte := in_file.read(1)):
                    ciphertext = self.rsa_cipher.encrypt_with_RSA(pub_key=pubkey, data=byte)
                    enc.append(ciphertext)


            print("[+] Forwarding new zone file and transaction block to Broker ...")
            # Serialize the encrypted data and send to the client
            msg = (enc, self.blockchain.current_transactions)
            self.client_sock.sendall(pickle.dumps(msg))

            # Send REGIS_DOMAIN flag to indicate EOL
            self.client_sock.sendall(REGIS_DOMAIN)

            enc, self.blockchain.current_transactions = [], []

        elif flag == CONSENSUS:
            print("[+] Sending request for update to Broker ...")

            # Send CONSENSUS flag to indicate update request
            self.client_sock.sendall(CONSENSUS)

    @staticmethod
    def get_pubkey(pubkey_dir):
        """
        Function to get Public Key of Alice
        @param pubkey_dir: <str> Directory of the client's Public Key
        @return:
        """
        rsa_cipher = RSACipher()
        return rsa_cipher.load_pubkey(pubkey_dir).publickey().exportKey(format='PEM', passphrase=None, pkcs=1)

    def user_menu(self):
        # Temporary menu system for Proof Of Concept (POC)
        # Client will be browser/proxy in the future
        while True:
            print(f"\n\t###### Today's Menu ######")
            print(f"\t[1] Register a new domain")
            print(f"\t[2] Resolve a domain")
            print(f"\t[3] Resolve an IP address")
            print(f"\t[4] Update Blockchain (Consensus)")
            print(f"\t[5] Print Blockchain")
            print(f"\t[6] Quit")

            try:
                user_option = input("\t >  ")
            except KeyboardInterrupt:
                user_option = "6"

            if user_option == "6":
                # User wants to quit
                print("\n[!] Bye!")
                self.client_sock.close()
                return False

            elif user_option == "1":
                # !! Currently not working !!
                # User wants to register a new domain
                print("[!] Option to register new domain chosen")
                if self.register_domain():
                    self.send_server(REGIS_DOMAIN)

            elif user_option == "2":
                # User wants to resolve a domain name
                print("[!] Option to resolve domain chosen")
                domain_name = input("[*] Enter domain name to resolve > ")
                self.resolve_domain(domain_name)

            elif user_option == "3":
                # User wants to resolve an IP address
                print("[!] Option to resolve IP address chosen")
                ip_addr = input("[*] Enter IP address to resolve > ")
                self.resolve_ip(ip_addr)
            elif user_option == "4":                
                # User wants to update dns records
                print("[!] Option to update DNS chosen")
                self.send_server(CONSENSUS)
                
            elif user_option == "5":
                # User wants to see Blockchain
                print("[!] Option to view Blockchain chosen")
                print(json.dumps(self.blockchain.chain, indent=4))


            else:
                # User doesn't know what he wants
                print("[*] Please select an option.")

    def register_domain(self):
        """
        Registers a new domain, currently only POC. Does not work fully.
        @return: <bool>
        """

        # Requesting for new domain name to register
        print("[+] Please enter your new domain name, without any prefix. (Eg. google.stack, youtube.stack)")
        new_domain_name = input(" >  ")

        # Does a check if domain already exists
        print("[+] Checking if domain is taken... Please wait")
        for block in self.blockchain.chain[1:]:
            # If the domain exists in the blockchain
            if (block["transactions"]["domain_name"]) == new_domain_name:
                print(f"[*] Domain {new_domain_name} already exists! Please choose another domain.")
                return False

        # Checks if domain exists in local directory of zone files
        for filename in os.listdir(ZONE_FILE_DIR):
            with open(os.path.join(ZONE_FILE_DIR, filename), "rb") as in_file:
                data = json.loads(in_file.read())

            for domains in data.keys():
                if domains == new_domain_name:
                    print(f"[*] Domain {new_domain_name} already exists! Please choose another domain.")
                    return False

        self.new_zone_fpath = f"client/{UUID}/{new_domain_name}.json"

        print("\n\t###### Registering new domain ######")
        print(f"\tClient: {UUID}")
        print(f"\tDomain Name: {new_domain_name}")
        print(f"\tZone File: {self.new_zone_fpath}")

        try:
            user_confirmation = input("\n[*] Continue? Y/N > ").upper()

        except KeyboardInterrupt:
            return False

        if user_confirmation == "Y":
            print(f"[+] Saving {new_domain_name} as a Zone File ...")
            # Save the domain name as a new zone file
            with open(self.new_zone_fpath, "w") as out_file:
                data = {
                    new_domain_name: [{
                        "subdomain": "www",
                        "data": self.get_rand_ip(),
                        "type": "A"
                    }]
                }
                out_file.write(json.dumps(data))

            self.blockchain.new_transaction(client=UUID, domain_name=new_domain_name,
                                            zone_file_hash=self.blockchain.generate_sha256(self.new_zone_fpath))
            return True

        return False

    def resolve_domain(self, domain_name):
        """
        Resolves domains
        @param domain_name: <str> Domain name to resolve to IP address
        @return: Returns True if domain is resolved, False otherwise
        """
        global CACHE_SITES
        # Iterate through CACHE_SITES first before looking in the Blockchain
        results_df = CACHE_SITES.loc[CACHE_SITES['domain_name'] == domain_name]        
        
        # If domain_name exist in CACHE Memory
        if not results_df.empty:
            print("\t[+] Found in Cache Sites ...") 
            domain_name, ip_addr, domain_type = results_df.values[0]
            print(f"\n\t###### {domain_name} ######")
            print("\n\t###### IP Addresses ######")
            print(f"\t{ip_addr}\t{domain_type}")
            return True
        
        print("\t[+] Not found in Cache, iterating through Blockchain now ...")
        # Create the blockchain DataFrame
        df = pd.DataFrame(self.blockchain.chain[1:])
        
        # Extract the Block that contains the domain name
        block_df = df.loc[df['transactions'].apply(lambda x: x["domain_name"] == domain_name)]            

        if not block_df.empty:
            block = block_df.to_dict(orient="records")[0]
            zone_file_hash = block["transactions"]["zone_file_hash"]

            if self.blockchain.verify_block(block):
                for fname in os.listdir(ZONE_FILE_DIR):
                    # Retrieves absolute path of filename
                    abs_path = os.path.join(os.path.abspath(ZONE_FILE_DIR), fname)
                    # Generates hash of absolute path
                    abs_path_hash = self.blockchain.generate_sha256(abs_path)
                    if abs_path_hash == zone_file_hash:
                        # Loads in zone file
                        with open(abs_path, "rb") as in_file:
                            data = json.loads(in_file.read())

                        # Loops through to locate requested domain
                        for domains in data.keys():
                            if domains == domain_name:
                                print(f"\n\t###### {domain_name} ######")
                                print("\n\t###### IP Addresses ######")
                                for i in data[domains]:
                                    
                                    # Add records in to CACHE_SITES DataFrame
                                    CACHE_SITES = CACHE_SITES.append({
                                        "domain_name": domain_name,
                                        "ip" : i['data'],
                                        "type": i['type']
                                        }, ignore_index=True)

                                    print(f"\t{i['type']}\t{i['data']}")

                                return True

        print("[*] Domain does not exist! Have you updated your zone file?")
        return False

    def resolve_ip(self, ip_address):
        """
        Resolves IP addresses
        @param ip_address: <str> IP address to resolve to domain name
        @return: Returns True if IP address is resolved, False otherwise
        """

        for filename in os.listdir(ZONE_FILE_DIR):
            # Retrieves absolute path of filename
            abs_path = os.path.join(os.path.abspath(ZONE_FILE_DIR), filename)
            # Loads in zone file
            with open(abs_path, "rb") as in_file:
                data = json.loads(in_file.read())

            # Loops through to locate requested IP address
            for domain in data.keys():
                for subdomains in data[domain]:
                    if subdomains["data"] == ip_address:
                        print("\n\t###### Domain Name ######")
                        print(f"\t{domain}")
                        return True

        print("[*] IP address does not exist! Have you updated your zone file?")
        return False

    @staticmethod
    def get_rand_ip():
        """
        Generate a random IP address
        @return: <str> IP Address
        """
        return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))


if __name__ == '__main__':
    # Create directory if it does not exist
    if not os.path.exists(os.path.dirname(DEFAULT_ZONE_FILE)):
        os.mkdir(os.path.dirname(DEFAULT_ZONE_FILE))

    # Run the client connection with the broker
    Client(HOST, PORT)
