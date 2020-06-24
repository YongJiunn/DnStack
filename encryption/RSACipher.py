"""
RSA Cipher Implementation

Author @ Zhao Yea 
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode


class RSACipher(object):
    # Load public key back from file
    def load_pubkey(self, pubkey_dir):
        with open(pubkey_dir, 'r') as pub_file:
            return RSA.importKey(pub_file.read())

    # Load private key from file
    def load_privkey(self, privkey_dir):
        with open(privkey_dir, 'r') as priv_file:
            return RSA.importKey(priv_file.read())

    def importRSAKey(self, key):
        return RSA.importKey(key)

    # Encryption Method
    def encrypt_with_RSA(self, pub_key, data):
        cipher = PKCS1_OAEP.new(pub_key)
        return b64encode(cipher.encrypt(data))

    # Decryption Method
    def decrypt_with_RSA(self, priv_key, data):
        cipher = PKCS1_OAEP.new(priv_key)
        return cipher.decrypt(b64decode(data))
