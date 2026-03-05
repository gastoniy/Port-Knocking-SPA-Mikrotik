import socket
from scapy.all import sniff, Raw, UDP

IP_ADDR: str = "127.0.0.220"
UDP_PORT: int = 62220

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_ADDR, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        try:
            print(f'{data}')

            response = b"ACK: Data received!\n"
            sock.sendto(response, addr)
        except Exception as e:
            print(f"Error: {e}")

def process_packet(packet):
    if packet.haslayer(UDP) and packet.haslayer(Raw):
        data = packet[Raw].load
    
    command = data.decode("utf-8")
    src_ip = packet["IP"].src

    print(command)

    
def run_server_scapy():
    bpf_filter = f"udp dst port {UDP_PORT}"

    sniff(iface="lo", filter=bpf_filter, prn=process_packet, store=0)

if __name__ == "__main__":
    run_server_scapy()