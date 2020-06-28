import hashlib
import time

m = hashlib.sha256()
m.update(b"100")
hash = m.hexdigest()


def proof_of_work(hash):
    """
    Proof of work calculation

    @param hash: <hashlib> Current hash of block
    @return: next_hash and proof
    """
    current_hash = hash
    proof = 0

    while True:
        proof += 1
        next_hash = hashlib.sha256(f'{current_hash * proof}'.encode()).hexdigest()

        if next_hash[0:4] == "0000":
            print(f"Current Hash: {current_hash}\n"
                  f"Proof: {proof}\n"
                  f"Next Hash: {next_hash}")
            break

    return proof


if __name__ == '__main__':
    print("[*] Proof of Work Program Starting ...")
    program_start = time.time()
    proof_of_work(hash)
    program_end = time.time()
    print("[TIME OF PROGRAM]", program_end - program_start, "seconds")
