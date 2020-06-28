import hashlib
import json

block = {
    "index": 1,
    "timestamp": 1593344359.8529475,
    "transactions": [],
    "proof": 100,
    "previous_hash": 1
}


def hash(block):
    """
    Create a SHA-256 hash of Block
    :param block: <dict> Block
    :return: <str> hash of block
    """

    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()


def proof_of_work(previous_hash):
    proof = 0

    while not valid_proof(previous_hash, proof):
        proof += 1

    return proof


def valid_proof(previous_hash, proof):
    next_hash = hashlib.sha256(f'{previous_hash * proof}'.encode()).hexdigest()
    return next_hash[:4] == "0000"


if __name__ == '__main__':
    print("[*] Proof of Work Program Starting ...")
    # program_start = time.time()
    previous_hash = hash(block)
    proof = proof_of_work(previous_hash)
    print(proof)

    # program_end = time.time()
    # print("[TIME OF PROGRAM]", program_end - program_start, "seconds")
