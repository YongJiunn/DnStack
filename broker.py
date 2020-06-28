"""
Eve Script (Server)

Author @ Zhao Yea 
"""

import pickle
import socket
import threading
import socketserver
import pandas as pd
import progressbar

from encryption.RSACipher import *

# Server Settings
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

# client session
CLIENTS = {"Users": []}


def get_username(user_db, user_id):
    user_df = pd.read_csv(user_db, sep=",", header=0)
    # Check whether the user_id exist in the ID column of dataframe
    if user_id in map(lambda x: str(x), user_df.id.values):
        return user_df.loc[user_df.id.isin([user_id])].name.to_string(index=False).lstrip()


class ThreadedServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        # Try catch the error
        try:
            # Get the user_id and public key
            user_id, self.user_pubkey = pickle.loads(self.request.recv(BUFSIZE))
            self.username = get_username(USER_DB_DIR, user_id)

            # Info message
            print(f"[*] {self.username} has started the connection.")

            # Add the client session
            CLIENTS["Users"].append({
                "id": self.request,
                "name": self.username
            })

            # Send Zone File to the client
            self.send_client(ZONE_FILE)


        # Close the socket if client forcefully close the connection
        except socket.error:
            self.delete_client()
            print(f"\n[*] {self.username} left the chat room.".encode())
            self.request.close()

    def send_client(self, flag):
        # Load the RSA Cipher
        rsa_cipher = RSACipher()
        pubkey = rsa_cipher.importRSAKey(self.user_pubkey)

        for session in CLIENTS["Users"]:
            client_sess = session['id']
            client_name = session['name']

            if client_sess == self.request:
                # Send the zone file over to the client
                if flag == "zone_file":
                    # Progress Bar just for fun # TODO Might change to another library like [tqdm]
                    bar = progressbar.ProgressBar(widgets=[f'[*] Sending Zone file to {client_name} ... ',
                                                           progressbar.Bar('=', '[', ']'), ' ',
                                                           progressbar.Percentage()])
                    bar.start()

                    # Send Zone File over to Client
                    with open(ZONE_DB_DIR, "rb") as in_file:
                        for line in in_file:
                            ciphertext = rsa_cipher.encrypt_with_RSA(pubkey, line.strip())
                            client_sess.send(ciphertext)

                    bar.finish()

    def delete_client(self):
        # Delete the client in the dictionary list
        for index in range(len(CLIENTS["Users"])):
            if CLIENTS["Users"][index]["id"] == self.request:
                del CLIENTS["Users"][index]


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    server = ThreadedServer((HOST, PORT), ThreadedServerHandle)

    print(f"[*] Server Started on {HOST}:{PORT}")

    # Start the server thread to thread every single client
    server_thread = threading.Thread(target=server.serve_forever())
    server_thread.start()
