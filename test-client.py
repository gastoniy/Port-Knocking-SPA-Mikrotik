import socket
import sys
from os import environ
from nacl.public import PrivateKey, PublicKey, Box
import time

# if len(sys.argv) != ... # Finish while cryptography implementation

server_ip = sys.argv[1]
server_port = int(sys.argv[2])
client_private_hex: str | None = environ.get("TEST_CLIENT_PRIVATE_KEY") # Getting as env var for tests purposes
server_public_hex: str | None = environ.get("SERVER_PUBLIC_KEY") # In future will be given as args to script

if not client_private_hex or not server_public_hex:
    raise ValueError("Missing PyNaCl key environment variables.")

client_priv = PrivateKey(bytes.fromhex(client_private_hex))
server_pub = PublicKey(bytes.fromhex(server_public_hex))
crypto_box = Box(client_priv, server_pub)
command = "Request for access via SPA"

timestamp = time.time()
payload = f"{command}|{timestamp}".encode("utf-8")

try:
    encrypted_token = crypto_box.encrypt(payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(encrypted_token, (server_ip, server_port))

    print(f"SPA packet sent to {server_ip}:{server_port}")
except Exception as e:
    print(f"While sending an error occurred: {e}")
