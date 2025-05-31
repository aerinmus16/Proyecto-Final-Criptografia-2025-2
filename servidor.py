import socket
import signal
import pickle
import sys
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Sockets y señales (setup, cierre)
server_socket = None
current_conn = None
clave_sesion_srv = None

def signal_handler(sig, frame):
    global server_socket, current_conn
    if current_conn:
        current_conn.close()
    if server_socket:
        server_socket.close()
    print("Sesión finalizada.")
    sys.exit(0)


#Autoridad, firmado y verificación
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

def firmar_nonce(clave_privada, nonce):
    return clave_privada.sign(nonce, ec.ECDSA(hashes.SHA256()))

def verificar_firma(clave_publica, nonce, firma):
    try:
        clave_publica.verify(firma, nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False
    
# ECDH
def generar_par_ecdh():
    clave_privada = ec.generate_private_key(ec.SECP384R1())
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def derivar_clave_sesion(clave_privada, clave_publica_remota):
    secreto_compartido = clave_privada.exchange(ec.ECDH(), clave_publica_remota)
    return secreto_compartido[:32]

def generar_nonce():    
    return os.urandom(16)

# Cifrado y descifrado de mensajes usando AES
def cifrar_mensaje(clave_sesion, mensaje):
    aesgcm = AESGCM(clave_sesion)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, mensaje.encode(), None)
    return nonce, ciphertext

def descifrar_mensaje(clave_sesion, nonce, ciphertext):
    aesgcm = AESGCM(clave_sesion)
    mensaje = aesgcm.decrypt(nonce, ciphertext, None)
    return mensaje.decode()
    
def main():
    global server_socket, current_conn
    signal.signal(signal.SIGINT, signal_handler)

    ra = AutoridadRegistro()
    servidor = "servidor"
    priv_key_servidor, pub_key_servidor = ra.registrar_entidad(servidor)
    dispositivo = "dispositivo"

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Servidor escuchando")
    current_conn, addr = server_socket.accept()
    print(f"Conexión establecida desde {addr}")

    # Recepción de la clave pública del dispositivo
    pub_key_dispositivo_bytes = current_conn.recv(256)
    pub_key_dispositivo = serialization.load_pem_public_key(pub_key_dispositivo_bytes)
    ra.registro[dispositivo] = pub_key_dispositivo

    # Envío de la clave pública del servidor
    pub_key_servidor_bytes = pub_key_servidor.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    current_conn.send(pub_key_servidor_bytes)

    # Proceso de autenticación mutua con el dispositivo
    nonce1 = generar_nonce()
    current_conn.send(nonce1)
    firma_dispositivo = current_conn.recv(256)
    if verificar_firma(pub_key_dispositivo, nonce1, firma_dispositivo):
        print("Dispositivo autenticado por el servidor")
    else:
        print("Fallo en autenticación del dispositivo")
        current_conn.close()
        server_socket.close()
        return
    nonce2 = current_conn.recv(256)
    firma_servidor = firmar_nonce(priv_key_servidor, nonce2)
    current_conn.send(firma_servidor)

    # Establecimiento de la clave de sesión con ECDH
    priv_srv_ecdh, pub_srv_ecdh = generar_par_ecdh()
    pub_srv_ecdh_bytes = pub_srv_ecdh.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    current_conn.send(pub_srv_ecdh_bytes)
    pub_dev_ecdh_bytes = current_conn.recv(256)
    pub_dev_ecdh = serialization.load_pem_public_key(pub_dev_ecdh_bytes)
    clave_sesion_srv = derivar_clave_sesion(priv_srv_ecdh, pub_dev_ecdh)
    print("Clave de sesión establecida con éxito")

    # Bucle para recibir y enviar mensajes cifrados
    while True:
        try:
            nonce_ciphertext_bytes = current_conn.recv(256)
            if not nonce_ciphertext_bytes:
                break
            nonce, ciphertext = pickle.loads(nonce_ciphertext_bytes)
            mensaje_descifrado = descifrar_mensaje(clave_sesion_srv, nonce, ciphertext)
            print(f"Servidor recibió: {mensaje_descifrado}")
            respuesta = input("Ingrese respuesta del servidor al dispositivo: ")
            nonce, ciphertext = cifrar_mensaje(clave_sesion_srv, respuesta)
            current_conn.send(pickle.dumps((nonce, ciphertext)))
        except (ConnectionResetError, BrokenPipeError, EOFError):
            break
        except KeyboardInterrupt:
            signal_handler(None, None)

    current_conn.close()
    server_socket.close()
    print("Sesión finalizada.")

if __name__ == "__main__":
    main()