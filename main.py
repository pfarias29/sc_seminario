import rsa

TAMANHO_MÓDULO = 2048
TAMANHO_MÓDULO_BYTES = TAMANHO_MÓDULO // 8

def main():
    message_file = 'teste.txt'

    message = 'Seminário de Segurança Computacional'

    public_key, private_key = rsa.generate_keys()

    cyphertext = rsa.rsa_encrypt(message.encode() , public_key)

    decrypted_message = rsa.rsa_decrypt(cyphertext, private_key).decode()

    file_signature = rsa.sign_file(message_file, private_key)

    verified = rsa.verify_file(message_file, file_signature, public_key)

    print(f'###TRABALHO DE SEGURANÇA COMPUTACIONAL###\n\n')

    print(f'#INFORMAÇÕES INICIAIS##\n')
    print(f'Mensagem original: {message}\n')
    print(f'Chave Pública: {public_key}\n')
    print(f'Chave Privada: {private_key}\n')

    print(f'#CRIPTOGRAFIA#\n')
    print(f'Mensagem cifrada: {cyphertext}\n')

    print(f'#DE CRIPTOGRAFIA#\n')
    print(f'Mensagem decifrada: {decrypted_message}\n')

    print(f'#ASSINATURA DIGITAL#\n')
    print(f'Assinatura digital: {file_signature}\n')

    if (verified):
        print(f'Verificação da assinatura: verdadeira\n')
    else:
        print(f'Verificação da assinatura: falsa\n')
    

if __name__ == '__main__':
    main()