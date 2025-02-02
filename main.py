import rsa

def main():
    message_file = 'teste.txt'
    pdf_file = 'CIC0201-2024-2-Seminario.pdf'

    message = 'Seminário de Segurança Computacional'

    public_key, private_key = rsa.generate_keys()

    cyphertext = rsa.rsa_encrypt(message.encode() , public_key)

    decrypted_message = rsa.rsa_decrypt(cyphertext, private_key).decode()

    file_signature = rsa.sign_file(message_file, private_key)
    pdf_file_signature = rsa.sign_file(pdf_file, private_key)

    verified = rsa.verify_file(message_file, file_signature, public_key)
    verified_pdf = rsa.verify_file(pdf_file, pdf_file_signature, public_key)

    print(f'###TRABALHO DE SEGURANÇA COMPUTACIONAL###\n\n')

    print(f'#INFORMAÇÕES INICIAIS##\n')
    print(f'Mensagem original: {message}\n')
    print(f'Chave Pública: {public_key}\n')
    print(f'Chave Privada: {private_key}\n')

    print(f'#CRIPTOGRAFIA#\n')
    print(f'Mensagem cifrada: {cyphertext}\n')

    print(f'#DECRIPTOGRAFIA#\n')
    print(f'Mensagem decifrada: {decrypted_message}\n')

    print(f'#ASSINATURA DIGITAL#\n')
    print(f'Assinatura digital: {file_signature}\n')
    print(f'Assinatura digital do PDF: {pdf_file_signature}\n')

    if (verified):
        print(f'Verificação da assinatura: verdadeira\n')
    else:
        print(f'Verificação da assinatura: falsa\n')

    if (verified_pdf):
        print(f'Verificação da assinatura do PDF: verdadeira\n')
    else:
        print(f'Verificação da assinatura do PDF: falsa\n')


if __name__ == '__main__':
    main()