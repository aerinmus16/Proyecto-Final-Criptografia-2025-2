import socket
import pickle
import signal
import sys
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Variables globales para manejo del socket
client_socket = None
clave_sesion_dev = None

# Manejador de señal para cerrar la conexión 
def signal_handler(sig, frame):
    global client_socket
    if client_socket:
        client_socket.close()
    print("Sesión finalizada.")
    sys.exit(0)

class AutoridadRegistro:
    def __init__(self):
        self.registro = {}

    def registrar_entidad(self, id_entidad):
        clave_privada = ec.generate_private_key(ec.SECP256R1())
        clave_publica = clave_privada.public_key()
        self.registro[id_entidad] = clave_publica
        return clave_privada, clave_publica

    def obtener_clave_publica(self, id_entidad):
        return self.registro.get(id_entidad)

# Función para generar un nonce aleatorio
def generar_nonce():
    return os.urandom(16)

# Función para firmar un nonce con ECDSA
def firmar_nonce(clave_privada, nonce):
    return clave_privada.sign(nonce, ec.ECDSA(hashes.SHA256()))

# Función para verificar la firma de un nonce con ECDSA
def verificar_firma(clave_publica, nonce, firma):
    try:
        clave_publica.verify(firma, nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False
