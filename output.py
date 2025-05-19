import streamlit as st 
import os
from dotenv import load_dotenv 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

def decrypt_aes(chave, texto_cifrado):
    mensagem_cifrada = unhexlify(texto_cifrado)
    cipher = AES.new(chave, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(mensagem_cifrada), AES.block_size)
    return pt.decode('utf-8')


def decrypt_des(chave, texto_cifrado):
    mensagem_cifrada = unhexlify(texto_cifrado)
    cifra = DES.new(chave, DES.MODE_ECB)
    mensagem_paded = cifra.decrypt(mensagem_cifrada)
    mensagem = unpad(mensagem_paded, DES.block_size)
    return mensagem.decode('utf-8')

def decrypt_rsa(chave, plain_text):
    load_dotenv()
    decifra = PKCS1_OAEP.new(chave)
    mensagem_cifrada_bytes = bytes.fromhex(plain_text)
    mensagem_decifrada = decifra.decrypt(mensagem_cifrada_bytes)
    return mensagem_decifrada.decode('utf-8')


load_dotenv()
chave_privada_pem = os.getenv("CHAVE_PRIVADA").replace("\\n", "\n")
chave_privada = RSA.import_key(chave_privada_pem)
with open("chave.txt", "r", encoding="utf-8") as chave_pass:
    mensagem_cifrada_hex = chave_pass.read()
with open("texto.txt", "r", encoding="utf-8") as texto:
    mensagem_original_cifrada = texto.read()

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
st.title("Texto descriptografado")
st.write(mensagem_descriptografada)