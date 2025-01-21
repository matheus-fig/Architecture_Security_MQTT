import subprocess
import atexit
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

# =========================
# Configurações
# =========================
IPTABLES_CHAIN = "OUTPUT"
QUEUE_NUM = "1"

def add_iptables_rule():
    """
    Adiciona a regra iptables para enviar os pacotes (da chain) à fila NFQUEUE 1
    """
    cmd = ["iptables", "-I", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    print(f"[+] Adicionando regra iptables: {' '.join(cmd)}")
    subprocess.run(["sudo"] + cmd, check=True)

def remove_iptables_rule():
    """
    Remove a regra iptables adicionada.
    """
    cmd = ["iptables", "-D", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    print(f"[-] Removendo regra iptables: {' '.join(cmd)}")
    subprocess.run(["sudo"] + cmd, check=False)

def extract_mqtt_features(packet):
    """
    Função para extrair as características MQTT de um pacote.
    """
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        return {
            'mqtt.len': len(raw_data),
            'mqtt.msg': raw_data[:50]  # Mostra os primeiros 50 bytes da carga útil
        }
    return {}

def main():
    # Adiciona a regra iptables antes de iniciar
    add_iptables_rule()
    # Remove automaticamente ao encerrar
    atexit.register(remove_iptables_rule)

    # Função callback da NetfilterQueue
    def process_packet(packet):
        scapy_pkt = IP(packet.get_payload())

        # Exibir informações do pacote
        ip_src = scapy_pkt[IP].src
        ip_dst = scapy_pkt[IP].dst

        if scapy_pkt.haslayer(TCP):
            sport = scapy_pkt[TCP].sport
            dport = scapy_pkt[TCP].dport
            flags = scapy_pkt[TCP].flags
            pkt_len = len(scapy_pkt)
            print(f"[PACKET] {ip_src}:{sport} -> {ip_dst}:{dport}, Flags={flags}, Length={pkt_len}")
        else:
            print(f"[PACKET] {ip_src} -> {ip_dst} (Não é TCP)")

        # Exibir features MQTT
        mqtt_features = extract_mqtt_features(scapy_pkt)
        if mqtt_features:
            print("[MQTT Features]")
            for feature, value in mqtt_features.items():
                print(f"{feature}: {value}")

        # Bloquear todos os pacotes MQTT
        if mqtt_features:
            print("[BLOCKED: PACOTE MQTT]")
            packet.drop()
        else:
            packet.accept()

    # Inicia a netfilterqueue
    nfqueue = NetfilterQueue()
    nfqueue.bind(int(QUEUE_NUM), process_packet)

    print(f"[+] Escutando pacotes na fila {QUEUE_NUM} (Ctrl+C para encerrar)")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("[!] Encerrando...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
