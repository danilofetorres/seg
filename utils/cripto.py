from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
from dotenv import load_dotenv 
from binascii import unhexlify

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