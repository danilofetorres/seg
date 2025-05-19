import streamlit as st
from input import criptografar_ui
from output import descriptografar_ui

st.title("App de Criptografia")

tab1, tab2 = st.tabs(["Criptografar", "Descriptografar"])

with tab1:
    criptografar_ui()

with tab2:
    descriptografar_ui()