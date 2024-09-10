import nmap
import sys
import socket
import struct
import ipaddress

def print_scan_result(host, scan_result):
    """Função para imprimir os resultados do escaneamento."""
    print(f'Host encontrado: {host}')
    if 'hostnames' in scan_result:
        print(f'  Nome do Host: {scan_result["hostnames"]}')
    if 'mac' in scan_result.get('addresses', {}):
        print(f'  MAC Address: {scan_result["addresses"].get("mac")}')
    print(f'  Estado: {scan_result.get("state")}')
    if 'osclass' in scan_result:
        print(f'  Sistema Operacional: {scan_result["osclass"]}')
    if 'osmatch' in scan_result:
        print(f'  Informações de Sistema: {scan_result["osmatch"]}')
    
    # Lista todas as portas abertas
    if 'tcp' in scan_result:
        print('  Portas abertas:')
        for port in scan_result['tcp']:
            print(f'    Porta {port}: {scan_result["tcp"][port]["name"]} ({scan_result["tcp"][port]["state"]})')
            
    if 'udp' in scan_result:
        print('  Portas UDP abertas:')
        for port in scan_result['udp']:
            print(f'    Porta {port}: {scan_result["udp"][port]["name"]} ({scan_result["udp"][port]["state"]})')

    print('')

def scan_network(network):
    """Realiza um escaneamento síncrono na rede especificada."""
    nm = nmap.PortScanner()
    print("Iniciando a varredura...")
    
    try:
        nm.scan(hosts=network, arguments='-A -T4')
        for host in nm.all_hosts():
            print_scan_result(host, nm[host])
    except Exception as e:
        print(f"Erro durante a varredura: {e}")

    print("Varredura concluída.")

def scan_current_network():
    nm = nmap.PortScanner()
    print("Iniciando a varredura no host local...")
    try:
        nm.scan('127.0.0.1', '22-443')
        print("Varredura concluída no host local.")
        print("Hosts encontrados:", nm.all_hosts())

        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    print('Porta : %s\tEstado : %s' % (port, nm[host][proto][port]['state']))
    except Exception as e:
        print(f"Erro ao escanear o host local: {e}")

def get_local_ip():
    """Obtém o endereço IP local."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_network_range(ip, subnet_mask):
    """Calcula o intervalo da rede baseado no IP e máscara de sub-rede."""
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    return str(network.network_address) + "/" + str(network.prefixlen)

def scan_local_network():
    local_ip = get_local_ip()
    subnet_mask = "255.255.255.0"  # Presumindo uma máscara de sub-rede padrão
    network = get_network_range(local_ip, subnet_mask)
    print(f"Iniciando a varredura na rede local: {network}")
    scan_network(network)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "network":
            if len(sys.argv) == 3:
                network_input = sys.argv[2]
                scan_network(network_input)
            else:
                print("Uso: python script.py network [rede]")
        elif command == "local":
            scan_current_network()
        elif command == "local_all":
            scan_local_network()
        else:
            print("Comando não reconhecido. Use 'network' para escanear uma rede específica, 'local' para escanear o host local, ou 'local_all' para escanear a rede local.")
    else:
        print("Uso: python script.py [network|local|local_all] [rede (opcional para 'network')]")
