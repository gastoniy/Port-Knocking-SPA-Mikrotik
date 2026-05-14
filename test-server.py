import os
import socket
import logging
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError
import yaml
import time
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

DATA_DIR = os.environ.get("SPA_DATA_DIR", "/app/data")  # Container Mount with required files
SPA_PORT = int(os.environ.get("SPA_PORT", 62201))
SPA_IFACE = "0.0.0.0"
MAX_AGE_SEC = int(os.environ.get("SPA_AGE", 10))
ROUTER_IP = os.environ.get("ROUTER_IP", "172.17.0.1")
ROUTER_USER: str = os.environ.get("ROUTER_USER", "")  # Will be changed
ROUTER_PASS: str = os.environ.get("ROUTER_PASS", "")
LIST_NAME = os.environ.get("SPA_LIST_NAME", "SPA_Auth")
OPEN_TIMEOUT = os.environ.get("SPA_OPEN_TIMEOUT", "00:05:00")   # Close the firewall pinhole after 5 minutes

def load_server_key() -> PrivateKey:
    '''
    Load private key from .key file
    Raise an error if private key file if not found
    '''
    try:
        with open(f"{DATA_DIR}/server_private.key", "r") as f:
            return(PrivateKey(bytes.fromhex(f.read().strip())))
    except FileNotFoundError:
        logging.error("server_private.key not found!")
        exit(1)

def load_clients() -> dict[str, dict[str, str]] | dict:    # Where str-key can be public key or comment
    """
    Load client public key from .yaml file
    Log if public keys file is not found
    """
    try:
        with open(f"{DATA_DIR}/clients.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config.get("clients", {})    # Return clients dict or empty dict
    except FileNotFoundError:
        logging.error("clients.yaml not found! Empty dict is returned!")
        return {}

def add_ip_to_firewall(ip_address: str) -> None:
    url = f"https://{ROUTER_IP}/rest/ip/firewall/address-list"
    payload = {
        "list": LIST_NAME,
        "address": ip_address,
        "timeout": OPEN_TIMEOUT,
    }

    try:
        response = requests.put(
            url,
            json=payload,
            auth=(ROUTER_USER, ROUTER_PASS),
            verify=False,
            timeout=5
        )

        if response.status_code in (200, 201):
            logging.info(f"Added {ip_address} to '{LIST_NAME}' for {OPEN_TIMEOUT}")
        else:
            logging.error(f"Router responded with {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        logging.error(f"API Connection failed: {e}")


def run_server() -> None:
    server_priv = load_server_key()
    clients_dict = load_clients()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SPA_IFACE, SPA_PORT))
    logging.info(f"SPA started listening on {SPA_IFACE}:{SPA_PORT}/UDP")

    while True:
        data, addr = sock.recvfrom(1024)

        # Try to decrypt the packet with each authorized client's public key until one succeeds
        authorized = False

        for client_name, client_items in clients_dict.items():
            try:
                client_pub = PublicKey(bytes.fromhex(client_items.get("public-key", "")))
                crypto_box = Box(server_priv, client_pub)

                decrypted = crypto_box.decrypt(data)
                payload = decrypted.decode("utf-8")

                authorized = True
                command, timestamp_str = payload.split('|')

                packet_time = float(timestamp_str)

                if abs(time.time() - packet_time) > MAX_AGE_SEC:
                    logging.warning(f"REPLAY DETECTED from {addr[0]}. Dropping.")
                    break   # Stop checking other keys because replay attack was detected
                
                logging.info(f"SPA server received a command: {command} from {client_name} on {addr[0]}")
                break   # Stop checking other keys since match was found 

            except CryptoError:
                # The packet could not be decrypted with this specific client's key - normal behavior
                continue
            
            except ValueError as ve:
                # This happens if the YAML has a bad hex string that can't be converted.
                logging.error(f"Failed to load key for '{client_name}' (Bad Hex format?): {ve}")
                continue

            except Exception as e:
                logging.error(f"SPA server returned unexpected error: {e}")
                continue

        if not authorized:
            logging.warning(f"Unauthorized or unreadable SPA packet from {addr[0]}")

        add_ip_to_firewall(addr[0])


if __name__ == "__main__":
    run_server()