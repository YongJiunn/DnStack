"""
128-bits AESCipher

Author: @ Tan Zhao Yea

Read More:
Advanced Encryption Standard: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
For more information: https://docs.python-guide.org/scenarios/crypto/
"""

import base64
import hashlib
import sys
from Crypto import Random
from Crypto.Cipher import AES
from passlib.hash import sha256_crypt


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32  # padding size
        self.hash_key = sha256_crypt.encrypt(key)  # create the sha 256 hash
        self.key = hashlib.sha256(key.encode()).digest()  # encode the key with message digest (hashlib.sha256)

    def encrypt(self, plaintext):
        plaintext = self._pad(plaintext)  # pad the plain text
        iv = Random.new().read(AES.block_size)  # generate a random IV

        # encrypt the text with the key, IV and specify the encryption mode: Cipher Block Chaining (CBC)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        cipherText = iv + cipher.encrypt(plaintext)

        # encode cipher text to base 64
        b64_cipherText = base64.b64encode(cipherText)

        # return the encrypted text and append the hash at the front of the cipher text (for integrity), seperating it with a '::'
        return self.hash_key + "::" + b64_cipherText

    def decrypt(self, pass_phrase, enc):
        hash_key = enc.split("::")[0]  # extract the hash_key
        b64_cipherText = enc.split("::")[1]  # extract the cipher text

        # verify the integrity of the hash
        if sha256_crypt.verify(pass_phrase, hash_key):
            enc = base64.b64decode(b64_cipherText)  # decode base64
            iv = enc[:AES.block_size]  # retrieve the iv
            cipher = AES.new(self.key, AES.MODE_CBC, iv)  # decrypt the cipher text to give you the plain text
            return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

        else:
            print("Incorrect passphrase entered.")  # exit the program if the incorrect passphrase is key
            sys.exit()

    # padding feature
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
