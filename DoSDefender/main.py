#!/usr/bin/env python3

import subprocess
import atexit
import joblib
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
from feature_extractor import extract_mqtt_features

# Carregamos o modelo treinado
modelo = joblib.load("modelo/mqtt_dos_model.pkl")

IPTABLES_CHAIN = "OUTPUT"        # ou INPUT, FORWARD, etc.
QUEUE_NUM = "1"

def add_iptables_rule():
    """
    Redirecionar pacotes da chain para a fila NFQUEUE 1
    Ex: sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
    """
    cmd = ["iptables", "-I", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    subprocess.run(["sudo"] + cmd, check=True)

def remove_iptables_rule():
    """
    Remove a regra criada
    Ex: sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
    """
    cmd = ["iptables", "-D", IPTABLES_CHAIN, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM]
    subprocess.run(["sudo"] + cmd, check=False)

def process_packet(packet):
    """
    Callback chamada para cada pacote que chega na fila do NetfilterQueue.
    """
    scapy_pkt = IP(packet.get_payload())

    # Verifique se é TCP e porta 1883, etc. (se quiser filtrar só MQTT)
    # Caso contrário, se quiser analisar tudo, tudo bem.
    if scapy_pkt.haslayer(TCP):
        # extrai as features
        features = extract_mqtt_features(scapy_pkt)

        # Convertendo pra array 2D (uma amostra só)
        # Supondo que seu modelo .predict espera shape (n, m)
        # Se vc sabe que o modelo usa DataFrame, então adequar.
        # Exemplo com numpy:
        import numpy as np
        X = np.array([features])

        # Faz predição
        y_pred = modelo.predict(X)
        # Se for 1 = Attack, 0 = Normal, por exemplo:
        if y_pred[0] == 1:
            print("[BLOCKED: POSSÍVEL DoS MQTT]", features)
            packet.drop()
            return

    # Se não bloqueou
    packet.accept()

def main():
    # Adiciona regra no iptables antes de tudo
    add_iptables_rule()
    # Remove ao sair
    atexit.register(remove_iptables_rule)

    nfqueue = NetfilterQueue()
    nfqueue.bind(int(QUEUE_NUM), process_packet)

    print("Analisando pacotes MQTT (DoS) em tempo real. Ctrl+C para sair.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Encerrando...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
