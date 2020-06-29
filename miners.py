"""
Miner Script

Author @ Zhao Yea
"""

import socket
import pickle

UUID = "3234739665"


class Miners(object):
    def __init__(self, host, port):
        """
        Initial Connection to the Broker Address
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: <sock> Client socket connection to the Broker
        """

        # Initial pull request for updated zone file
        self.request_record(host, port)

    def request_record(self, host, port):
        """
        Connects to the broker and requests for an update blockchain + zone file
        @param host: <str> IP Addr of the Broker
        @param port: <int> Port number of the Broker
        @return: Returns True if blockchain + zonefile was updated successfully, False otherwise
        """

        print(f"[*] Connecting to Broker @ ({host},{port})")

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
        server_hello_msg = (UUID, "")
        self.client_sock.send(pickle.dumps(server_hello_msg))
