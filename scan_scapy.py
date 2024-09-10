from scapy.all import ARP, Ether, srp
import sys

def scan_network(network):
    # Cria um pacote ARP para a faixa de IPs fornecida
    arp = ARP(pdst=network)
    # Cria um pacote Ethernet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combina os pacotes
    packet = ether/arp

    # Envia o pacote e recebe as respostas
    result = srp(packet, timeout=3, verbose=0)[0]

    # Analisa as respostas e extrai informações
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python scanner.py [IP/faixa]")
        print("Exemplo: python scanner.py 192.168.1.0/24")
        sys.exit(1)

    network = sys.argv[1]
    devices = scan_network(network)

    print("Dispositivos encontrados na rede:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print(device)
