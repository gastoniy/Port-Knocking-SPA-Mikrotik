import socket
import sys

# if len(sys.argv) != ... # Finish while cryptography implementation

server_ip = sys.argv[1]
server_port = int(sys.argv[2])
# secret_key = sys.argv[3]

command: bytes = b"Request for access via SPA"

try:
    token = command # Add cryptography in the next stage
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(token, (server_ip, server_port))

    print(f"SPA packet sent to {server_ip}:{server_port}")
except Exception as e:
    print(f"While sending an error occurred: {e}")
