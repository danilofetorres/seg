import streamlit as st 
import os
from dotenv import load_dotenv 
from Crypto.PublicKey import RSA
from utils.cripto import *

def descriptografar_ui():
    load_dotenv()
    chave_privada_pem = os.getenv("CHAVE_PRIVADA").replace("\\n", "\n")
    chave_privada = RSA.import_key(chave_privada_pem)
    chave_publica_pem = os.getenv("CHAVE_PUBLICA").replace("\\n", "\n")
    chave_publica = RSA.import_key(chave_publica_pem)
    arquivo_lido = 0
    try:
        with open("chave.txt", "r", encoding="utf-8") as chave_pass:
            mensagem_cifrada_hex = chave_pass.read()
        with open("texto.txt", "r", encoding="utf-8") as texto:
            mensagem_original_cifrada = texto.read()
        with open("user.txt", "r", encoding="utf-8") as usuario:
            usuario_autenticacao = usuario.read()
    except:
        pass
    try:    
        with open("autenticacao.txt", "r",  encoding="utf-8") as autenticacao:
            hash_autenticacao = autenticacao.read()
        arquivo_lido = 1
    except:
        arquivo_lido = 0
    autenticacao = 0
    
    if arquivo_lido == 1:
        assinatura = bytes.fromhex(hash_autenticacao)
        h = SHA256.new(("Texto escrito por " + usuario_autenticacao).encode())
        try:
            pkcs1_15.new(chave_publica).verify(h, assinatura)
            autenticacao = 1
        except:
            autenticacao = 0
    #texto_autenticacao = decrypt_rsa(chave_publica, usuario_autenticacao)
    #antes, separador, depois = texto_autenticacao.partition("Texto escrito por ")

    # if separador: 
    #     parte1 = separador 
    #     parte2 = depois.strip()
    #     if parte2 == '':
    #         raise ValueError("Não foi feita autenticação de usuário.")
    # else:
    #     raise ValueError("Não foi feita autenticação de usuário.")
    try:
        mensagem_descriptografada = ''
        if mensagem_cifrada_hex != '':
            texto_original = decrypt_rsa(chave_privada, mensagem_cifrada_hex)
            algoritmo, chave_simetrica = texto_original.split(" ")
            match algoritmo:
                case 'DES':
                    print(len(bytes.fromhex(chave_simetrica)))
                    print(bytes.fromhex(chave_simetrica))
                    mensagem_descriptografada = decrypt_des(bytes.fromhex(chave_simetrica), mensagem_original_cifrada)
                case 'AES':
                    mensagem_descriptografada = decrypt_aes(bytes.fromhex(chave_simetrica), mensagem_original_cifrada)
                case _:
                    raise ValueError(f"Algoritmo inválido: {algoritmo}")
        else:
            mensagem_descriptografada = decrypt_rsa(chave_privada, mensagem_original_cifrada)
    except:
        pass
    if autenticacao == 1:
        st.write("Texto escrito por " + usuario_autenticacao)
    else:
        st.write("Não foi possível autenticar remetente.")
    try:    
        if(mensagem_original_cifrada != ''):
            st.title("Texto criptografado")
            st.write(mensagem_original_cifrada)
    except:
        pass
    st.title("Texto descriptografado")
    st.write(mensagem_descriptografada)