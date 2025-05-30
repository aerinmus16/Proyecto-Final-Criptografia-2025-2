import socket
import signal
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

#Sockets y señales (setup, cierre)
server_socket = None
current_conn = None

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
    
def main():
    global server_socket, current_conn
    signal.signal(signal.SIGINT, signal_handler)

    ra = AutoridadRegistro()
    servidor = "servidor"
    priv_key_servidor, pub_key_servidor = ra.registrar_entidad(servidor)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Servidor escuchando")
    current_conn, addr = server_socket.accept()
    print(f"Conexión establecida desde {addr}")
    current_conn.close()
    server_socket.close()
    print("Sesión finalizada.")

if __name__ == "__main__":
    main()