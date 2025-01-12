"""
main.py

Script principal que:
1) Configura iptables para redirecionar pacotes para a NetfilterQueue
2) Faz a leitura (scapy) e extração de features
3) Carrega o modelo de ML para detectar ataques MQTT DoS
4) Bloqueia pacotes se o modelo indicar ataque
5) Remove a regra iptables ao encerrar
"""

# IMPORTS
import subprocess
import atexit
import joblib
import numpy as np

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# Import da função de extração de features
from feature_extractor import extract_mqtt_features

# =======================
# CONFIGURAÇÕES
# =======================

# Nome da chain onde a regra será adicionada (ex.: "OUTPUT", "INPUT", "FORWARD")
IPTABLES_CHAIN = "OUTPUT"
# Número da fila do NetfilterQueue
QUEUE_NUM = "1"
# Caminho para o modelo treinado
MODELO_PATH = "modelo/mqtt_dos_model.pkl"

# Carrega o modelo de ML
print(f"Carregando modelo de ML a partir de {MODELO_PATH} ...")
model = joblib.load(MODELO_PATH)
print("Modelo carregado com sucesso!")

def add_iptables_rule():
    """
    Adiciona a regra iptables para enviar pacotes à fila do netfilter.
    Exemplo: sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
    """
    cmd = ["iptables", "-I", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    print(f"Adicionando regra iptables: {' '.join(cmd)}")
    subprocess.run(["sudo"] + cmd, check=True)

def remove_iptables_rule():
    """
    Remove a regra iptables que foi adicionada.
    Exemplo: sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
    """
    cmd = ["iptables", "-D", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    print(f"Removendo regra iptables: {' '.join(cmd)}")
    subprocess.run(["sudo"] + cmd, check=False)

def process_packet(packet):
    """
    Callback chamada para cada pacote na fila do NetfilterQueue.
    Extrai as features e faz a predição com o modelo de ML.
    Se for ataque (1), bloqueia (drop); se for normal (0), aceita.
    """
    scapy_pkt = IP(packet.get_payload())

    # (Opcional) Verificar se é TCP e porta 1883, se quiser filtrar só MQTT
    # if scapy_pkt.haslayer(TCP) and (scapy_pkt[TCP].dport == 1883 or scapy_pkt[TCP].sport == 1883):

    # Extrair as 17 features definidas
    features = extract_mqtt_features(scapy_pkt)

    # Converter para array numpy, shape (1, 17)
    X = np.array([features], dtype=object)

    # Faz predição
    y_pred = model.predict(X)

    if y_pred[0] == 1:
        print("[BLOCKED: POSSÍVEL ATAQUE MQTT DoS]", features)
        packet.drop()
    else:
        # Liberar o pacote
        packet.accept()

def main():
    # Adiciona a regra iptables antes de iniciar a captura
    add_iptables_rule()
    atexit.register(remove_iptables_rule)

    nfqueue = NetfilterQueue()
    nfqueue.bind(int(QUEUE_NUM), process_packet)

    print(f"Escutando pacotes na fila {QUEUE_NUM} do NetfilterQueue. (Ctrl+C para encerrar)")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
