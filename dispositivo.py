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

# Función para generar un par de claves ECDH
def generar_par_ecdh():
    clave_privada = ec.generate_private_key(ec.SECP384R1())
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

# Función para derivar la clave de sesión usando ECDH
def derivar_clave_sesion(clave_privada, clave_publica_remota):
    secreto_compartido = clave_privada.exchange(ec.ECDH(), clave_publica_remota)
    return secreto_compartido[:32]

# Función para cifrar mensajes con AES-GCM
def cifrar_mensaje(clave_sesion, mensaje):
    aesgcm = AESGCM(clave_sesion)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, mensaje.encode(), None)
    return nonce, ciphertext

# Función para descifrar mensajes con AES-GCM
def descifrar_mensaje(clave_sesion, nonce, ciphertext):
    aesgcm = AESGCM(clave_sesion)
    mensaje = aesgcm.decrypt(nonce, ciphertext, None)
    return mensaje.decode()

# Función principal del dispositivo
def main():
    global client_socket, clave_sesion_dev
    signal.signal(signal.SIGINT, signal_handler)

    # Inicialización de la autoridad de registro y registro del dispositivo
    ra = AutoridadRegistro()
    dispositivo = "dispositivo"
    priv_key_dispositivo, pub_key_dispositivo = ra.registrar_entidad(dispositivo)

    # Conexión al servidor mediante socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print("Conectado al servidor.")

    # Envío de la clave pública del dispositivo al servidor
    pub_key_dispositivo_bytes = pub_key_dispositivo.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket.send(pub_key_dispositivo_bytes)

    # Recepción de la clave pública del servidor
    pub_key_servidor_bytes = client_socket.recv(256)
    pub_key_servidor = serialization.load_pem_public_key(pub_key_servidor_bytes)
    ra.registro["servidor"] = pub_key_servidor
