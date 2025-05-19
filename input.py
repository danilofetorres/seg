import streamlit as st 
import os
from dotenv import load_dotenv 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def gravar_arquivo(texto):
    f = open('texto.txt', 'w')
    f.write(texto)
    f.close()

def gravar_chave(texto):
    f = open('chave.txt', 'w')
    f.write(texto)
    f.close()

def aes(plain_text):
    chave = get_random_bytes(16)
    cipher = AES.new(chave, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return chave, ct_bytes.hex()

def des(plain_text):
    chave = get_random_bytes(8)
    cifra = DES.new(chave, DES.MODE_ECB)
    mensagem_paded = pad(plain_text.encode('utf-8'), DES.block_size)
    mensagem_cifrada = cifra.encrypt(mensagem_paded)
    return chave, mensagem_cifrada.hex()

def rsa(plain_text):
    load_dotenv()
    chave_publica_pem = os.getenv("CHAVE_PUBLICA").replace("\\n", "\n")
    chave_publica = RSA.import_key(chave_publica_pem)
    cifra = PKCS1_OAEP.new(chave_publica)
    mensagem_cifrada = cifra.encrypt(plain_text.encode())
    return mensagem_cifrada.hex()


def criptografar():
    cifrado = ''
    chave = ''
    chave_cifrada = ''
    match algoritmo:
        case 'DES':
            chave, cifrado = des(texto)
            gravar_arquivo(texto)
        case 'AES':
            chave, cifrado = aes(texto)
        case 'RSA':
            cifrado = rsa(texto)
    if algoritmo != "RSA":
        chave_cifrada = rsa(algoritmo + ' ' + chave.hex())
    gravar_chave(chave_cifrada)
    gravar_arquivo(cifrado)

st.title("Insira o texto")

texto = st.text_input("Insira o texto às claras")

algoritmo = st.selectbox("Escolha um algoritmo de criptografia:", ("DES", "AES", "RSA"))
st.button("Criptografar", on_click=criptografar)