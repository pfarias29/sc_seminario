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
