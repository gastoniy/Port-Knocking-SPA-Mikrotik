import os
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

SPA_PORT = int(os.environ.get("SPA_PORT", 62201))
SPA_IFACE: str = "0.0.0.0" # Listen on all the containers' ports

def run_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SPA_IFACE, SPA_PORT))
    logging.info(f"SPA started listening on {SPA_IFACE}:{SPA_PORT}/UDP")

    while True:
        data, addr = sock.recvfrom(1024)
        try:
            payload = data.decode("utf-8")
            logging.info(f"SPA server received a payload: {payload} from {addr[0]}")
        except Exception as e:
            logging.error(f"SPA server returned unexpected error: {e}")

if __name__ == "__main__":
    run_server()