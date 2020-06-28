import json
import hashlib

from blockchain import Blockchain

ZONE_FILE_DIR = r"database/dns_zone.json"
google_pubkey = "b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiCAyA5SFjbNrE8C2GXtk/aoV6YRu\ndr3ifJklYd+YjT3Oj6Uss6V8lzwbSIDuXP/1x2LGu4Mopi4we0m6uSJV8A==\n-----END PUBLIC KEY-----'"


def sha256(data):
    hash_sha256 = hashlib.sha256(data.encode())
    return hash_sha256.hexdigest()


def main():
    blockchain = Blockchain()

    with open(ZONE_FILE_DIR, "rb") as in_file:
        data = json.loads(in_file.read())

    for domain_name in data.keys():
        print(f"Domain Name: {domain_name}")
        blockchain.new_transaction(domain_name=domain_name,
                                   pubkey=google_pubkey,
                                   zone_file_hash=sha256(ZONE_FILE_DIR))

        # Mining happens
        last_block = blockchain.last_block
        previous_hash = blockchain.hash(last_block)
        print(f"Previous Hash: {previous_hash}")

        proof = blockchain.proof_of_work(previous_hash)
        print(f"Proof: {proof}")

        blockchain.new_block(proof=proof, previous_hash=previous_hash)

    print(json.dumps(blockchain.chain, indent=4))


if __name__ == '__main__':
    main()
