'''
Implementação de gerador e verificador de assinaturas RSA

-> Parte 1: geração de chaves e cifra
    + Geração de chaves (p e q primos com no mínimo 1024  bits)
    + Cifração/decifração assimétrica RSA usando OAEP
-> Parte 2: assinatura 
    + Cálculo de hasjes da mensagem (SHA-3)
    + Assinatura da mensagem
    + Formatação do resultado (caracteres especiais e informações para verificação em BASE64)
-> Parte 3: verificação 
    + Parsing do documento assinado e decifração da mensagem
    + Decifração da assinatura
    + Verificação da assinatura
'''
from random import randrange
from sympy import isprime
from math import gcd


def random_number_1024_bits():
    # Gera um número aleatório de 1024 bits
    return randrange((2**1023) + 1, (2**1024) - 1)

def generate_p_q():
    # Geração dos primos p e q e checagem de primalidade
    p, q = 0, 0

    while not isprime(p):
        p = random_number_1024_bits()
        if p % 2 == 0:
            continue
        if isprime(p):
            break
    while not isprime(q):
        q = random_number_1024_bits()
        if q % 2 == 0:
            continue
        if isprime(q):
            break

    return p, q

def algoritmo_euclidiano_estendido(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        gcd, x, y = algoritmo_euclidiano_estendido(b, a % b)
        return (gcd, y, x - (a // b) * y)

def mod_inverse(e, phi):
    # Cálculo do inverso multiplicativo de e mod phi
    gcd, x, _ = algoritmo_euclidiano_estendido(e, phi)
    if gcd != 1:
        return None
    return x % phi

def gernerate_keys(p, q):
    #Cálculo de n e phi(n)
    n = p * q
    phi_n = (p-1) * (q-1)

    # Valor inicial comumente usado para e
    e = 65537
    while gcd(e, phi_n) != 1:
        e += 2

    # Cálculo de d
    # d . e ≡ 1 (mod phi(n)); d = e^(-1) mod phi(n) 
    d = mod_inverse(e, phi_n)

    if (d == None):
        print ("Não foi possível calcular o valor da chave privada")
        return None, None

    return (e, n), (d, n)

if __name__ == "__main__":

    print("Gerando chaves...")
    p, q = generate_p_q()
    public_key, private_key = gernerate_keys(p, q)
    if (public_key == None):
        print("Erro na geração das chaves")
        exit()
    print("Chaves geradas com sucesso!")
    print("Chave pública: ", public_key)
    print("Chave privada: ", private_key)