"""
Alice Prototype (Client)

Author @ Zhao Yea
"""

import re
import socket
import pickle

from encryption.RSACipher import *

HOST, PORT = "localhost", 1337
BUFSIZE = 2048
Alice_pubkey_dir = r"client/Alice_pubkey.pub"
CACHE_SITES = []


def get_pubkey():
    """ Function to get Public Key of Alice """
    rsa_cipher = RSACipher(Alice_pubkey_dir, None)
    return rsa_cipher.load_pubkey()


def initial_communication():
    # Establishing Connection to the Server
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST, PORT))

    # Send client pubkey over to server on initial connection
    client_sock.send(get_pubkey())

    return client_sock


def main():
    """ Main and Core function """
    client_sock = initial_communication()

    try:
        while True:
            data = client_sock.recv(BUFSIZE).decode()

            if not data:
                break

            print(data)
            # Construct the Default Message to be send over to server
            while True:
                client_input = input("[>]: ")
                if not client_input in ("", " ", "\n"):
                    break

            # uuid = (re.findall(r'.\[(\d+?)]', data))[0]
            client_sock.send(client_input.encode())

    except KeyboardInterrupt:
        client_sock.close()

    except socket.error:
        client_sock.close()


if __name__ == '__main__':
    main()
