import sqlite3
from scapy.all import sniff, IP
from collections import Counter
import sys

def create_db():
    conn = sqlite3.connect('packets.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER
        )
    ''')
    conn.commit()
    print("Banco packets.db criado/aberto com sucesso!")
    return conn, c

def insert_packet(c, src, dst, proto, length):
    print(f"Inserindo pacote: {src} -> {dst} | {proto} | {length} bytes")
    c.execute('INSERT INTO packets (src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?)', (src, dst, proto, length))

def get_protocol(pkt):
    if pkt.haslayer('TCP'):
        return 'TCP'
    elif pkt.haslayer('UDP'):
        return 'UDP'
    elif pkt.haslayer('ICMP'):
        return 'ICMP'
    else:
        return 'OTHER'

def main():
    iface = input("Digite a interface de rede para capturar pacotes (ex: eth0, wlan0): ").strip()
    try:
        count = int(input("Digite o número de pacotes a capturar: "))
    except ValueError:
        print("Número inválido.")
        sys.exit(1)

    conn, cursor = create_db()

    packets_data = []

    print(f"Capturando {count} pacotes na interface {iface}...")

    def process_packet(pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = get_protocol(pkt)
            length = len(pkt)
            packets_data.append((src, dst, proto, length))
            insert_packet(cursor, src, dst, proto, length)

    sniff(iface=iface, prn=process_packet, count=count)

    conn.commit()
    print("Dados gravados no banco com sucesso!")

    total = len(packets_data)
    proto_counter = Counter([p[2] for p in packets_data])
    src_counter = Counter([p[0] for p in packets_data])
    dst_counter = Counter([p[1] for p in packets_data])

    print("\nEstatísticas de Tráfego:")
    print(f"Total de pacotes capturados: {total}")
    print("Pacotes por protocolo:")
    for proto, qnt in proto_counter.most_common():
        print(f"  {proto}: {qnt}")
    print("IPs de origem:")
    for ip, qnt in src_counter.most_common(5):
        print(f"  {ip}: {qnt} pacotes")
    print("IPs de destino:")
    for ip, qnt in dst_counter.most_common(5):
        print(f"  {ip}: {qnt} pacotes")

    conn.close()
    print("Conexão com banco fechada.")

if __name__ == '__main__':
    main()
