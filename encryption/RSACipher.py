"""
RSA Cipher Implementation

Author @ Zhao Yea 
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode


class RSACipher(object):
    def __init__(self, pubkey_dir, privkey_dir=None):
        self.pubkey_dir = pubkey_dir
        self.privkey_dir = privkey_dir

    # Load public key back from file
    def load_pubkey(self):
        with open(self.pubkey_dir, 'r') as pub_file:
            return RSA.importKey(pub_file.read())

    # Load private key from file
    def load_privkey(self):
        with open(self.privkey_dir, 'r') as priv_file:
            return RSA.importKey(priv_file.read())

    # Encryption Method
    def encrypt_with_RSA(self, pub_key, data):
        cipher = PKCS1_OAEP.new(pub_key)
        return b64encode(cipher.encrypt(data))

    # Decryption Method
    def decrypt_with_RSA(self, priv_key, data):
        cipher = PKCS1_OAEP.new(priv_key)
        return cipher.decrypt(b64decode(data))
