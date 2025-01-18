import subprocess
import atexit
import numpy as np
import joblib
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
from packet_detector import MQTTPacketDetector

# =========================
# Configurações
# =========================
SVM_MODEL_PATH = "/home/lab-iot03/DoSDefender2/modelo/scaler.pkl"
SCALER_PATH = "/home/lab-iot03/DoSDefender2/modelo/svm_model.pkl"
LABEL_ENCODER_PATH = "modelo/label_encoder.pkl"  # se existir
CATEGORICAL_COLS = ['mqtt.protoname']  # colunas categóricas, se for o caso

# Qual chain do iptables capturar (ex.: "OUTPUT", "INPUT", "FORWARD")
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
        # Aqui você precisa de uma função para decodificar e extrair as informações MQTT.
        # Supondo que você tenha algum parser MQTT, como o do scapy, ou implementações próprias.

        # Exemplo de como poderiam ser as features MQTT (isso depende do seu parser MQTT):
        mqtt_features = {
            'mqtt.conack.flags': None,  # Extraia conforme a estrutura do seu protocolo
            'mqtt.conflag.cleansess': None,
            'mqtt.conflags': None,
            'mqtt.dupflag': None,
            'mqtt.hdrflags': None,
            'mqtt.kalive': None,
            'mqtt.len': len(raw_data),
            'mqtt.msg': raw_data[:50],  # Mostra os primeiros 50 bytes da carga útil
            'mqtt.msgid': None,
            'mqtt.msgtype': None,
            'mqtt.proto_len': None,
            'mqtt.protoname': None,  # Nome do protocolo MQTT
            'mqtt.qos': None,
            'mqtt.ver': None,
        }

        # Extração de features específicas
        # Adapte a extração conforme a estrutura MQTT do pacote
        # Exemplo: mqtt.qos = raw_data[0] (isto depende do formato)

        return mqtt_features
    return {}

def main():
    # 1) Inicializa o detector (SVM + Scaler + LabelEncoder)
    detector = MQTTPacketDetector(
        svm_model_path=SVM_MODEL_PATH,
        scaler_path=SCALER_PATH,
        label_encoder_path=LABEL_ENCODER_PATH,
        categorical_columns=CATEGORICAL_COLS
    )
    print("[+] Detector MQTT (SVM) carregado com sucesso.")

    # 2) Adiciona a regra iptables antes de iniciar
    add_iptables_rule()
    # Remove automaticamente ao encerrar
    atexit.register(remove_iptables_rule)

    # 3) Função callback da NetfilterQueue
    def process_packet(packet):
        scapy_pkt = IP(packet.get_payload())

        # ------------------------
        # EXIBIR INFORMAÇÕES DO PACOTE
        # ------------------------
        ip_src = scapy_pkt[IP].src
        ip_dst = scapy_pkt[IP].dst

        if scapy_pkt.haslayer(TCP):
            sport = scapy_pkt[TCP].sport
            dport = scapy_pkt[TCP].dport
            flags = scapy_pkt[TCP].flags
            time_delta = scapy_pkt[TCP].time
            pkt_len = len(scapy_pkt)
            print(f"[PACKET] {ip_src}:{sport} -> {ip_dst}:{dport}, Flags={flags}, Time Delta={time_delta}, Length={pkt_len}")
        else:
            # Se não for TCP, apenas mostra IPs
            print(f"[PACKET] {ip_src} -> {ip_dst} (Não é TCP)")

        # ------------------------
        # EXIBIR FEATURES MQTT
        # ------------------------
        mqtt_features = extract_mqtt_features(scapy_pkt)
        print("[MQTT Features]")
        for feature, value in mqtt_features.items():
            print(f"{feature}: {value}")

        # ------------------------
        # CHECAR SE É ATAQUE
        # ------------------------
        if detector.is_attack(scapy_pkt):
            print("[BLOCKED: POSSÍVEL ATAQUE MQTT DoS]")
            packet.drop()
        else:
            packet.accept()

    # 4) Inicia a netfilterqueue
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
