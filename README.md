# Port-Knocking-SPA-Mikrotik

> **Single Packet Authorization (SPA) server for MikroTik RouterOS v7**
> A lightweight, containerized SPA server written in Python that enables secure, cryptographically authenticated firewall access — by sending a single encrypted UDP packet.

---

## Table of Contents

- [What is SPA?](#what-is-spa)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
  - [1. Prepare Keys](#1-prepare-keys)
  - [2. Prepare Configuration Files](#2-prepare-configuration-files)
  - [3. Build the Docker Image](#3-build-the-docker-image)
  - [4. Deploy on MikroTik](#4-deploy-on-mikrotik)
    - [CHR (Cloud Hosted Router)](#chr-cloud-hosted-router)
    - [Physical MikroTik Device](#physical-mikrotik-device)
  - [5. Using the Client](#5-using-the-client)
- [Configuration Reference](#configuration-reference)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [License](#license)

---

## What is SPA?

Traditional port knocking opens a port after receiving a sequence of connection attempts to specific ports. **Single Packet Authorization** (SPA) goes further: access is only granted after receiving a **single, cryptographically signed and encrypted UDP packet** containing a timestamp. The firewall port does not need to be open at all before the packet is received — there is nothing for a scanner to find.

This project implements SPA for **MikroTik routers running RouterOS v7**, using the router's built-in container support to run a lightweight Python server alongside the router's firewall.

---

## How It Works

```
[Client]                        [MikroTik Container]              [RouterOS Firewall]
   |                                     |                                |
   |  Encrypted UDP packet (NaCl Box)    |                                |
   |-----------------------------------> |                                |
   |                                     |  Decrypt & verify timestamp    |
   |                                     |  Match against known clients   |
   |                                     |  Call REST API                 |
   |                                     |------------------------------> |
   |                                     |  Add src IP to address-list    |
   |                                     |  with configured timeout       |
   |                                     |<------------------------------ |
   |  [Access now allowed by firewall]   |                                |
```

1. The client encrypts a command + timestamp with [NaCl](https://nacl.cr.yp.to/) Box encryption (X25519 + XSalsa20-Poly1305).
2. The SPA server receives the UDP packet and attempts decryption with each known client's key.
3. If decryption succeeds, the timestamp is validated against a configurable replay-attack window.
4. The server calls the MikroTik REST API to add the client's source IP to a firewall address list with a timeout.
5. RouterOS firewall rules use this address list to grant temporary access.

---

## Project Structure

```
.
├── test-server.py          # SPA server (runs inside the container)
├── test-client.py          # SPA client (runs on your machine)
├── keys_generator.py       # Utility to generate X25519 key pairs
├── requirements.txt        # Python dependencies (PyNaCl, PyYAML, requests)
├── dockerfile              # Multi-stage Docker build
├── clients.example.yaml    # Example client keys configuration on Router
├── config.example.yaml     # Example server setting configuration on Router
└── README.md
```

---

## Prerequisites

- **MikroTik RouterOS v7.4+** with the container package installed
  → [MikroTik Containers — Official Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)
- Docker (on your build machine) to build the image
- Python 3.10+

---

## Installation & Setup

### 1. Prepare Keys

Generate a key pair for the **server** and for each **client** using the provided utility:

```bash
python keys_generator.py
```

Example output:
```
Generated keys:
Private: a1b2c3d4e5f6...   ← Keep this secret. This is your server or client private key.
Public:  f6e5d4c3b2a1...   ← Share this with the other side.
```

Run it once for the server and once per client. Keep all private keys secret.

---

### 2. Prepare Configuration Files

You need three files placed inside your container's data volume (e.g. `sata/spa-server/data/`):

**`server_private.key`** — plain text file containing the server's private key hex string:
```
a1b2c3d4e5f6...
```

**`config.yaml`** — main server configuration (see `config.example.yaml`):
```yaml
server:
  port: 62201
  interface: "0.0.0.0" 
  max_age_sec: 10    

router:
  ip: "172.17.0.1"  
  user: "spa-api"  
  password: "your_password"

firewall:
  list_name: "SPA_Auth"   
  open_timeout: "00:05:00"
```

**`clients.yaml`** — registered client public keys (see `clients.example.yaml`):
```yaml
clients:
  my_laptop:
    public-key: "f6e5d4c3b2a1..."
    comment: "Personal laptop"
  work_phone:
    public-key: "aabbccddeeff..."
    comment: "Work mobile"
```

---

### 3. Build the Docker Image

```bash
# Clone the repository
git clone https://github.com/your-username/Port-Knocking-SPA-Mikrotik.git
cd Port-Knocking-SPA-Mikrotik

# Build the image
docker build -t spa-server .

# Export as a .tar file for MikroTik
docker save spa-server -o spa-server.tar
```

> **ARM-based MikroTik devices** (hAP, RB4xx, etc.) require a cross-compiled image. Pass `--platform linux/arm/v7` or `--platform linux/arm64` to `docker build` depending on your device's architecture. Check your device's CPU architecture in RouterOS under `System → Resources`.

---

### 4. Deploy on MikroTik

Before deploying, make sure containers are enabled on your router.
→ [How to enable container support on RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container#Container-Enablingcontainermode)

#### CHR (Cloud Hosted Router)

Transfer the image and data files to your CHR's disk (e.g. via FTP/SCP/Winbox Files):

```
sata/
├── spa-server.tar
└── spa-server/
    └── data/
        ├── config.yaml
        ├── clients.yaml
        └── server_private.key
```

Then configure the container in RouterOS terminal:

```routeros
# 1. Create a virtual ethernet interface for the container
/interface/veth/add name=veth-spa address=172.20.0.2/24 gateway=172.20.0.1

# 2. Create a bridge and add veth to it (so the container can reach the router)
/interface/bridge/add name=br-spa
/interface/bridge/port/add bridge=br-spa interface=veth-spa
/ip/address/add address=172.20.0.1/24 interface=br-spa

# 3. Create the mount (maps host directory into container)
/container/mounts/add name=spa_mount src=sata/spa-server/data dst=/app/data

# 4. Create environment variables (optional overrides)
/container/envs/add name=spa_env key=SPA_DATA_DIR value=/app/data

# 5. Add the container
/container/add \
  file=sata1/spa-server.tar \
  interface=veth-spa \
  mounts=spa_mount \
  logging=yes \
  root-dir=sata/spa-server/ \
  envs=spa_env \
  user="appuser:appuser"

# 6. Start the container (get the container number from /container/print)
/container/start 0
```

#### Physical MikroTik Device

The process is identical to CHR. The main differences are:

- Use the correct storage path for your device (e.g. `disk1/` for USB, `flash/` for internal flash).
- Build your Docker image with the correct architecture for your device.
- Transfer files using Winbox → Files, FTP, or `scp`.

#### Firewall Rules

Add a RouterOS firewall rule to drop all external access by default, then allow IPs from the SPA address list:

```routeros
# Allow traffic from authenticated SPA clients
/ip/firewall/filter/add \
  chain=input \
  src-address-list=SPA_Auth \
  action=accept \
  comment="SPA Authenticated Access" \
  place-before=0

# Drop everything else on the relevant port/service
/ip/firewall/filter/add \
  chain=input \
  dst-port=22 \
  protocol=tcp \
  action=drop \
  comment="Drop SSH by default"
```

Also allow the SPA UDP port through the firewall:
```routeros
/ip/firewall/filter/add \
  chain=input \
  protocol=udp \
  dst-port=62201 \
  action=accept \
  comment="Allow SPA packets"
```

---

### 5. Using the Client

Install dependencies:
```bash
pip install PyNaCl PyYAML requests
```

Create a client config at `~/.config/spa_client/config.yaml`:
```yaml
client_private_key: "your_client_private_key_hex"
server_public_key:  "your_server_public_key_hex"
```

Or use environment variables:
```bash
export SPA_CLIENT_PRIVATE_KEY="your_client_private_key_hex"
export SPA_SERVER_PUBLIC_KEY="your_server_public_key_hex"
```

Send an SPA packet:
```bash
# Basic usage (default port 62201)
python test-client.py 203.0.113.1

# Custom port and command
python test-client.py 203.0.113.1 -p 62201 -c "Request Open via SPA"

# Custom config path
python test-client.py 203.0.113.1 --config /path/to/config.yaml
```

After a successful packet, your IP will appear in the `SPA_Auth` address list in RouterOS for the configured timeout duration.

---

## Configuration Reference

| File | Location in container | Purpose |
|---|---|---|
| `config.yaml` | `/app/data/config.yaml` | Server, router, and firewall settings |
| `clients.yaml` | `/app/data/clients.yaml` | Client public keys |
| `server_private.key` | `/app/data/server_private.key` | Server private key (hex) |

**Environment variable overrides:**

| Variable | Default | Description |
|---|---|---|
| `SPA_DATA_DIR` | `/app/data` | Path to the data directory |
| `SPA_CONFIG_FILE` | `config.yaml` | Config filename inside data dir |

---

## Security Notes

- **Never commit private keys** — they are excluded from the repository via `.gitignore`.
- The replay attack window (`max_age_sec`) requires both the client and server clocks to be reasonably synchronized (NTP recommended).
- The RouterOS REST API user (`spa-api`) should have the minimum required permissions — only `write` access to `/ip/firewall/address-list`.
- The container runs as a non-root user (`appuser`, UID 1001) to limit the blast radius of any vulnerability.
- HTTPS verification to the router is currently disabled (`verify=False`) since RouterOS uses a self-signed certificate. If you use a trusted certificate on your router, remove this flag.

---

## Roadmap

This is **v1** of the SPA server — a working proof of concept built as a learning project. Planned improvements include:

- Refactoring the server into proper OOP design patterns (separating networking, crypto, and firewall logic into dedicated classes)
- IPv6 support
- Reload clients and config without restarting the container
- Unit tests and CI pipeline

---

## About This Project

This project was built by a Cybersecurity student as a hands-on exploration of network security concepts, Python systems programming, and MikroTik RouterOS — motivated by a genuine interest in DevOps, networking, and infrastructure security.

Feedback, issues, and pull requests are very welcome.

---

## License

[MIT](LICENSE) © 2026 Ihor Fisak