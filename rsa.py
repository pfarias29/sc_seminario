'''
Implementação de gerador e verificador de assinaturas RSA

-> Parte 1: geração de chaves e cifra
    + Geração de chaves (p e q primos com no mínimo 1024  bits)
    + Cifração/decifração assimétrica RSA usando OAEP
-> Parte 2: assinatura 
    + Cálculo de hashes da mensagem (SHA-3)
    + Assinatura da mensagem
    + Formatação do resultado (caracteres especiais e informações para verificação em BASE64)
-> Parte 3: verificação 
    + Parsing do documento assinado e decifração da mensagem
    + Decifração da assinatura
    + Verificação da assinatura
'''
from sympy import randprime
from random import randrange, getrandbits, randint
from hashlib import sha3_256
from base64 import b64encode, b64decode 

NUM_BITS = 1024
SEED_LENGTH = 256
PADDING_LENGTH = 256

def miller_rabin(n, d):
    a = randint(2, n - 2)
    x = pow(a, d, n)

    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = pow(x, 2, n)
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False

def isprime(n, k=5):
    
    if n == 2:
        return True

    if n < 2 or n % 2 == 0:
        return False

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(k):
        if not miller_rabin(n, d):
            return False
        
    return True




def gen_prime():
    while True:
        min_bits = 2 ** (NUM_BITS - 1)
        max_bits = 2 ** NUM_BITS - 1

        prime_number = randprime(min_bits, max_bits)

        if isprime(prime_number):
            return prime_number

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    m0, y, x = m, 0, 1

    if m == 1:
        return 0

    while a > 1:
        q = a // m
        m, a = a % m, m
        y, x = x - q * y, y
    
    return x + m0 if x < 0 else x


def generate_keys():
    p = gen_prime()
    q = gen_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    while gcd(e, phi) != 1:
        e = randrange(2, phi)

    d = mod_inverse(e, phi)

    return (e, n), (d, n)

def xor_bytes(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


def mgf1(seed, mask_len):
    hlen = sha3_256().digest_size

    output = b""

    for i in range(0, -(-mask_len // hlen)):
        c = i.to_bytes(4, 'big')
        output += sha3_256(seed + c).digest()

    return output[:mask_len]

def oaep_encode(message, n):
    mlen = len(message)
    pad = b'\x00' * (n - mlen - PADDING_LENGTH // 8 - 2)
    db = pad + b'\x01' + message

    seed = getrandbits(SEED_LENGTH).to_bytes(SEED_LENGTH // 8, 'big')
    db_mask = mgf1(seed, len(db))
    masked_db = xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, SEED_LENGTH // 8)
    masked_seed = xor_bytes(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db


def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    k = (n.bit_length() + 7) // 8 
    encoded_message = oaep_encode(plaintext, k)
    plaintext_int = int.from_bytes(encoded_message, 'big')
    ciphertext = pow(plaintext_int, e, n)

    return ciphertext


def oaep_decode(encoded_message, k):
    encoded_message = encoded_message[1:]

    masked_seed = encoded_message[:SEED_LENGTH // 8]
    masked_db = encoded_message[SEED_LENGTH // 8:]

    seed_mask = mgf1(masked_db, SEED_LENGTH // 8)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, len(masked_db))
    db = xor_bytes(masked_db, db_mask)

    lhash_len = len(sha3_256().digest())
    ps_end = db.index(b'\x01', lhash_len)
    message = db[ps_end + 1:]

    return message


def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    k = (n.bit_length() + 7) // 8
    plaintext_int = pow(ciphertext, d, n)
    plaintext = plaintext_int.to_bytes(k, 'big')

    return oaep_decode(plaintext, k)


def calculate_hash(file_path):    
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha3_256().update(chunk)

    return sha3_256().digest()


def sign_file(file_path, private_key):
    hash = calculate_hash(file_path)
    signature = rsa_encrypt(hash, private_key)
    formatted_signature = b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, 'big')).decode()

    return formatted_signature


def verify_file(file_path, base64_signature, public_key):
    signature = int.from_bytes(b64decode(base64_signature), 'big')
    decrypted_hash = rsa_decrypt(signature, public_key)
    current_hash = calculate_hash(file_path)

    return decrypted_hash == current_hash
