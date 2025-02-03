import os
import sys
import signal
import time
import logging
import subprocess
import threading
import pyshark
import pickle

############################################
# 1. CONFIGURAÇÕES DE LOG
############################################
def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("mqtt_blocker.log"),
            logging.StreamHandler()
        ]
    )

############################################
# 2. FUNÇÕES DE PREPROCESSAMENTO E CLASSIFICAÇÃO
############################################
def preprocess_value(value):
    """Substitui 'N/A' por 0."""
    return 0 if value == 'N/A' else value

def preprocess_flags(flags):
    """
    Remove o prefixo '0x' e preenche com zeros se necessário.
    Exemplo: remove "0x" e preenche para 5 dígitos.
    """
    if flags.startswith("0x"):
        return flags[2:].zfill(5)
    return flags.zfill(5)

def load_model(model_path):
    """Carrega o modelo de IA a partir do arquivo .pkl especificado."""
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

def classify_packet(model, features):
    """Executa a predição com base nas features extraídas."""
    prediction = model.predict([features])
    # Considere que o modelo pode retornar 1 ou "attack" para indicar um ataque.
    if str(prediction[0]).lower() in ["attack", "1"]:
        return 1
    return 0

############################################
# 3. THREAD DE DETECÇÃO
############################################
attack_flag = 0
attack_lock = threading.Lock()

def detection_thread_func(interface, capture_filter, model):
    """
    Captura pacotes em tempo real utilizando PyShark.
    Extrai as features:
      - flags (processadas para remover o '0x')
      - time_delta
      - length
    Se o modelo retornar 1, define attack_flag=1; caso contrário, 0.
    """
    global attack_flag
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    logging.info("Thread de detecção iniciada.")
    for packet in capture.sniff_continuously():
        try:
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                flags_str = preprocess_flags(tcp_layer.flags)
                time_delta = preprocess_value(getattr(tcp_layer, 'time_delta', 'N/A'))
                length = preprocess_value(getattr(tcp_layer, 'len', 'N/A'))
                flags_int = int(flags_str)
                time_delta_f = float(time_delta)
                length_int = int(length)
                features = [flags_int, time_delta_f, length_int]
                prediction = classify_packet(model, features)
                logging.info(f"Classificação do pacote: {prediction}")
                with attack_lock:
                    # Define attack_flag como 1 se houver ataque; caso contrário, 0.
                    attack_flag = 1 if prediction == 1 else 0
        except Exception as e:
            logging.error(f"Erro ao processar pacote: {e}")

############################################
# 4. BLOQUEIO DE PACOTES MQTT VIA IPTABLES
############################################
def block_mqtt_packets():
    """Bloqueia todos os pacotes MQTT utilizando iptables (porta 1883)."""
    logging.info("Bloqueando pacotes MQTT via iptables...")
    try:
        subprocess.run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "1883", "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", "1883", "-j", "DROP"], check=True)
        logging.info("Pacotes MQTT bloqueados com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao bloquear pacotes MQTT: {e}")

def reset_iptables():
    """Restaura as regras do iptables para o padrão removendo o bloqueio de MQTT."""
    logging.info("Resetando as regras do iptables para o padrão...")
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "1883", "-j", "DROP"], check=True)
        logging.info("Regra INPUT para MQTT removida com sucesso.")
    except subprocess.CalledProcessError:
        logging.warning("Regra INPUT para MQTT não encontrada ou já removida.")
    try:
        subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", "1883", "-j", "DROP"], check=True)
        logging.info("Regra OUTPUT para MQTT removida com sucesso.")
    except subprocess.CalledProcessError:
        logging.warning("Regra OUTPUT para MQTT não encontrada ou já removida.")

############################################
# 5. THREAD DE CONTROLE DO BLOQUEIO MQTT
############################################
def mqtt_block_control_thread_func():
    """
    Loop que verifica periodicamente a variável 'attack_flag'.
    Quando a flag for 1 pela primeira vez, bloqueia todos os pacotes MQTT.
    Uma vez bloqueado, o bloqueio permanece ativo.
    """
    global attack_flag
    mqtt_blocked = False
    logging.info("Thread de controle para bloqueio de pacotes MQTT iniciada.")
    while True:
        time.sleep(2)  # Verifica a cada 2 segundos
        with attack_lock:
            current_flag = attack_flag
        if current_flag == 1 and not mqtt_blocked:
            logging.info("[BLOCK] Ataque detectado -> bloqueando pacotes MQTT.")
            block_mqtt_packets()
            mqtt_blocked = True

############################################
# 6. MANEJO DE SINAIS E LIMPEZA
############################################
def handle_exit(signal_received, frame):
    logging.info("Recebido sinal de saída. Limpando regras do iptables...")
    reset_iptables()
    sys.exit(0)

############################################
# 7. MAIN
############################################
def main():
    configure_logging()
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    logging.info("Iniciando script de detecção e bloqueio de MQTT.")
    
    modelo_path = "/home/lab-iot03/Detector/ada_model.pkl"
    try:
        model = load_model(modelo_path)
        logging.info(f"Modelo de IA carregado de: {modelo_path}")
    except Exception as e:
        logging.error(f"Erro ao carregar o modelo: {e}")
        sys.exit(1)
    
    interface = "wlo1"
    capture_filter = "tcp or mqtt"
    
    detection_thread = threading.Thread(
        target=detection_thread_func,
        args=(interface, capture_filter, model),
        daemon=True
    )
    detection_thread.start()
    
    mqtt_block_thread = threading.Thread(
        target=mqtt_block_control_thread_func,
        daemon=True
    )
    mqtt_block_thread.start()
    
    # Loop principal para manter o script ativo
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
