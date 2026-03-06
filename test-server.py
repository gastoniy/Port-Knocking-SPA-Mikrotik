import os
import socket
import logging
from nacl.public import PrivateKey, PublicKey, Box

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

SERVER_PRIVATE_KEY_HEX = os.environ.get("SERVER_PRIVATE_KEY")
CLIENT_PUBLIC_KEY_HEX = os.environ.get("TEST_CLIENT_PUBLIC_KEY")
SPA_PORT = int(os.environ.get("SPA_PORT", 62201))
SPA_IFACE: str = "0.0.0.0" # Listen on all the containers' ports

if not SERVER_PRIVATE_KEY_HEX or not CLIENT_PUBLIC_KEY_HEX:
    raise ValueError("Missing PyNaCl key environment variables.")

server_priv = PrivateKey(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
client_pub = PublicKey(bytes.fromhex(CLIENT_PUBLIC_KEY_HEX))
crypto_box = Box(server_priv, client_pub)

def run_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SPA_IFACE, SPA_PORT))
    logging.info(f"SPA started listening on {SPA_IFACE}:{SPA_PORT}/UDP")

    while True:
        data, addr = sock.recvfrom(1024)

        try:
            decrypted = crypto_box.decrypt(data)
            payload = decrypted.decode("utf-8")
            
            logging.info(f"SPA server received a payload: {payload} from {addr[0]}")
        except Exception as e:
            logging.error(f"SPA server returned unexpected error: {e}")

if __name__ == "__main__":
    run_server()