"""
Eve Script (Server)

Author @ Zhao Yea 
"""

import re
import random
import socket
import pickle
import threading
import socketserver
import pandas as pd

# Server Settings
HOST, PORT = "0.0.0.0", 1336
BUFSIZE = 2048

# Users Database
USER_DB_DIR = r"database/Users.json"

# Admin
server_reply = "(Server)"

# FLAGS
JOIN = "joined"
EXIT = "exit"
WELCOME = "welcome"
WRONG_USERNAME = "wrong_user"
LISTUSER = "listuser"
HELPMENU = "helpmenu"

# Display Help Menu Page
HELP_PAGE = \
    f"""
    [STACK BETA SERVER]
    {"=" * 20} HELP MENU {"=" * 20} 
    COMMANDS:           DESCRIPTION
    ?, -h, -help        Display this help page
    -l, -list           List current active Users
    @username           Send File to Message
    enter               Send Message
    ctrl c              Exit the Program    
    {"=" * 51}
    """


def load_user_list(uname_dir):
    """
    Load the User Database and append them into a dictionary
    :param uname_dir: <str> Directory of the User database
    :return: <dict> Dictionary of the User database
    """
    user_db = pd.read_json(uname_dir)
    return user_db


class ThreadedServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        # Load the user database
        self.user_db = load_user_list(USER_DB_DIR)

        # Request for username
        self.request.sendall("What is your username: ".encode())

        # Try catch the error
        try:
            # Get the username and public key
            self.username, self.user_pubkey = pickle.loads(self.request.recv(BUFSIZE))

            if not self.username:
                self.request.close()

            elif not bool(re.match("^[a-zA-Z]+$", self.username)):
                self.kick(WRONG_USERNAME)

            else:
                # New User join into the server
                if self.username not in self.user_db:
                    new_user_id = str(random.getrandbits(32))
                    # Add the client id
                    new_user = pd.DataFrame({
                        self.username: [new_user_id, str(self.user_pubkey), self.request]
                    }, index=["uuid", "pubkey", "session"])

                    # Update the Database
                    self.user_db = pd.concat([self.user_db, new_user], axis=1)
                    self.update_db()

                # Update the User Session
                self.user_db[self.username].session = self.request

                # Info message
                print(f"[*] {self.username} joined the chat room.")

                # Welcome message to the user
                self.send_client(WELCOME)

                # Run the message handle
                self.message_handle()

        # Close the socket if client forcefully close the connection
        except socket.error:
            self.request.close()

    def message_handle(self):
        while True:
            # Receive Client send message and strip the '\n'
            self.data = self.request.recv(BUFSIZE).decode().strip()

            # Delete the user session if client unexpectedly shut down / close connection to server
            if not self.data:
                self.del_client_sess()
                self.update_db()
                print(f"[*] {self.username} left the chat room.")
                self.request.close()

            # List all the active clients in the chat room
            if self.data == '-l' or self.data == '-list':
                self.send_client(LISTUSER)

            # Display the Help page menu as long as user key in a value that does not exist in the help menu
            elif not self.data in ['-l', '-list', '@']:
                self.send_client(HELPMENU)

            # elif "@" in self.data:
            #     receiver = re.search("@([a-zA-Z]+)", self.data)
            #     if receiver:
            #         self.recv_client = receiver.group(1)
            #         self.send_client(PRIVATE)

    def send_client(self, flag):
        client_sess = self.user_db[self.username].session
        client_uuid = self.user_db[self.username].uuid

        if client_sess == self.request:
            # Welcome Message when the user first join
            if flag == "welcome":
                welcome_msg = f'{server_reply}: Hi {self.username}, this is your uuid: [{client_uuid}].' \
                              f'\n Here is what you can do:\n{HELP_PAGE}'
                client_sess.send(welcome_msg.encode())

            elif flag == "listuser":
                active_users = []
                for username in self.user_db.columns.tolist():
                    if self.user_db[username].session != "":
                        active_users.append(username)

                room_size = f"\nActive Users: {active_users}\nRoom Size: {len(active_users)}"
                client_sess.send(room_size.encode())

            elif flag == "helpmenu":
                client_sess.send(HELP_PAGE.encode())

    def del_client_sess(self):
        # Delete the client session in the database
        self.user_db[self.username].session = ""

    def kick(self, flag):
        if flag == "wrong_user":
            kick_msg = "Username can only contains string and no spaces at all!"
            self.request.sendall(kick_msg.encode())

        self.request.close()

    def update_db(self):
        # Update the database
        self.user_db.to_json(USER_DB_DIR, orient="columns")


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    server = ThreadedServer((HOST, PORT), ThreadedServerHandle)

    print(f"[*] Server Started on {HOST}:{PORT}")

    # Start the server thread to thread every single client
    server_thread = threading.Thread(target=server.serve_forever())
    server_thread.start()
