import socket
import argparse
import time
import os
import sys
import yaml
from pathlib import Path
from nacl.public import PrivateKey, PublicKey, Box


class SPAClient():
    def __init__(self, config_path: str | None = None) -> None:
        self.config: dict = self._load_config(config_path)
        self.crypto_box: Box = self._load_crypto_box()
    
    def _load_config(self, config_path: str | None) -> dict:
        """Load configuration from yaml file or returns empty dict"""
        default_path = Path.home() / ".config" / "spa_client" / "config.yaml"
        target_path = Path(config_path) if config_path else default_path

        if target_path.exists():
            print(f"Using config: {target_path}")
            with open(target_path, 'r') as f:
                return yaml.safe_load(f) or {}
        print("Config is not found! Trying env variables!")
        return {}
    
    def _load_crypto_box(self) -> Box:
        """Initialize crypto key from config OR env variables"""
        # Priority: Env vars -> Config File
        client_priv_hex = os.environ.get("SPA_CLIENT_PRIVATE_KEY") or self.config.get("client_private_key", None)
        server_pub_hex = os.environ.get("SPA_SERVER_PUBLIC_KEY") or self.config.get("server_public_key", None)

        if not client_priv_hex or not server_pub_hex:
            raise ValueError("Cryptographic keys were not found! Check your config file or env variables!")
        
        try:
            client_priv = PrivateKey(bytes.fromhex(client_priv_hex))
            server_pub = PublicKey(bytes.fromhex(server_pub_hex))
            return Box(client_priv, server_pub)
        except ValueError as e:
            raise ValueError(f"Wrong key format: {e}")
        
    def send_packet(self, server_ip: str, server_port: str, command: str = "Request Open via SPA") -> None:
        """Encrypt and send SPA packet via UDP"""
        timestamp = time.time()
        payload = f"{command}|{timestamp}".encode("utf-8")

        try:
            encrypted_token = self.crypto_box.encrypt(payload)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(encrypted_token, (server_ip, server_port))
            print(f"Sent encrypted SPA token to {server_ip}:{server_port}")
            print(f"Command sent: {command}")
        except socket.error as e:
            print(f"Network error while sending: {e}")
        except Exception as e:
            print(f"Unexpected Error: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Single Packet Authorization (SPA) Client")
    parser.add_argument("server_ip", help="Destination Server IP")
    parser.add_argument("-p", "--port", type=int, default=62201, help="UDP port of SPA Server (Default 62201)")
    parser.add_argument("-c", "--command", type=str, default="Request Open via SPA", help="Command to process (Default 'Request Open via SPA')")
    parser.add_argument("--config", type=str, help="Not standard path to configuration file")

    args = parser.parse_args()

    try:
        client = SPAClient(config_path=args.config)
        client.send_packet(args.server_ip, args.port, args.command)
    except ValueError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\nStopped by User", file=sys.stderr)
        sys.exit(0)

if __name__ == "__main__":
    main()