import streamlit as st 
from utils.cripto import *

def gravar_arquivo(texto):
    f = open('texto.txt', 'w')
    f.write(texto)
    f.close()

def gravar_chave(texto):
    f = open('chave.txt', 'w')
    f.write(texto)
    f.close()

def autenticar(texto):
    f = open('autenticacao.txt', 'w')
    f.write(texto)
    f.close()

def usuario(texto):
    f = open('user.txt', 'w')
    f.write(texto)
    f.close()
    
def criptografar(texto, algoritmo, remetente):
    autenticacao = rsa_autenticacao("Texto escrito por " + remetente)
    autenticar(autenticacao)
    usuario(remetente)
    try:
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
    except:
        pass

def criptografar_ui():
    st.title("Insira o texto")
    texto = st.text_input("Insira o texto às claras")
    remetente = st.text_input("Digite seu nome:")
    algoritmo = st.selectbox("Escolha um algoritmo de criptografia:", ("DES", "AES", "RSA"))
    st.button("Criptografar", on_click=criptografar, args=(texto, algoritmo, remetente))