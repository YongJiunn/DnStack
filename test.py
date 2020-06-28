import json
import hashlib

from blockchain import Blockchain

ZONE_FILE_DIR = r"database/dns_zone.json"
UUID = "4226355408"


def sha256(fname):
    file_hash = hashlib.sha256()
    with open(fname, "rb") as in_file:
        for chunk in iter(lambda: in_file.read(4096), b""):
            file_hash.update(chunk)

    return file_hash.hexdigest()


def main():
    blockchain = Blockchain()

    with open(ZONE_FILE_DIR, "rb") as in_file:
        data = json.loads(in_file.read())

    for domain_name in data.keys():
        print(f"Domain Name: {domain_name}")
        blockchain.new_transaction(client=UUID,
                                   domain_name=domain_name,
                                   zone_file_hash=sha256(ZONE_FILE_DIR))

        # Mining happens
        last_block = blockchain.last_block
        previous_hash = blockchain.block_hash(last_block)
        print(f"Previous Hash: {previous_hash}")

        proof = blockchain.proof_of_work(previous_hash)
        print(f"Proof: {proof}")

        blockchain.new_block(proof=proof, previous_hash=previous_hash)

    print(json.dumps(blockchain.chain, indent=4))


if __name__ == '__main__':
    main()
