# Cálculo de hash da mensagem
from hashlib import sha3_256

def hash_message(message):

    with open(message, 'rb') as file:
        message = file.read()

        sha3_256_hash = sha3_256()
        sha3_256_hash.update(message)

        return sha3_256_hash.hexdigest()
    