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
            logging.FileHandler("suricata_ips_setup.log"),
            logging.StreamHandler()
        ]
    )

############################################
# 2. DEFINIÇÃO DAS FUNÇÕES SURICATA
############################################
def check_suricata_installation():
    """Check if Suricata is installed."""
    try:
        subprocess.run(["suricata", "--build-info"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("Suricata is installed.")
    except FileNotFoundError:
        logging.error("Suricata is not installed. Please install it before running this script.")
        sys.exit(1)

def configure_suricata_for_ips():
    """Configures Suricata for IPS mode using NFQUEUE."""
    logging.info("Configuring Suricata for IPS mode...")
    suricata_config_path = "/etc/suricata/suricata.yaml"

    # Ajusta suricata.yaml para usar nfqueue
    try:
        with open(suricata_config_path, "r") as file:
            config = file.read()

        # Exemplo: substitui '- nflog' por '- nfqueue'
        if "- nflog" in config:
            config = config.replace("- nflog", "- nfqueue")

        with open(suricata_config_path, "w") as file:
            file.write(config)

        logging.info(f"Updated {suricata_config_path} to enable NFQUEUE mode.")
    except FileNotFoundError:
        logging.error(f"Configuration file {suricata_config_path} not found.")
        sys.exit(1)

    # Configura regras de iptables para NFQUEUE
    try:
        logging.info("Setting up iptables rules for NFQUEUE...")
        subprocess.run(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        subprocess.run(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("iptables rules configured successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set iptables rules: {e}")
        sys.exit(1)

def reset_iptables():
    """Reset iptables rules to default."""
    logging.info("Resetting iptables rules to default...")
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("iptables rules reset successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reset iptables rules: {e}")

def is_suricata_running():
    """Check if Suricata is already running."""
    try:
        result = subprocess.run(["pgrep", "-f", "suricata"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return (result.returncode == 0)
    except Exception as e:
        logging.error(f"Error checking Suricata status: {e}")
        return False

def start_suricata():
    """Start Suricata in IPS mode."""
    if is_suricata_running():
        logging.info("Suricata is already running. Skipping start.")
        return
    logging.info("Starting Suricata in IPS mode...")
    try:
        subprocess.Popen(["suricata", "--af-packet", "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("Suricata started successfully.")
    except FileNotFoundError:
        logging.error("Failed to start Suricata. Ensure it is installed correctly.")
        sys.exit(1)

def stop_suricata():
    """Stop Suricata."""
    if not is_suricata_running():
        logging.info("Suricata is not running. Skipping stop.")
        return
    logging.info("Stopping Suricata...")
    try:
        subprocess.run(["pkill", "-f", "suricata"], check=True)
        logging.info("Suricata stopped successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to stop Suricata: {e}")

############################################
# 3. DETECTOR
############################################
def preprocess_value(value):
    """Substitui 'N/A' por 0."""
    return 0 if value == 'N/A' else value

def preprocess_flags(flags):
    """
    Remove o prefixo '0x' e mantém os dígitos restantes, preenchendo com zeros se necessário.
    Ajuste caso seu modelo espere decimal/hex.
    """
    if flags.startswith("0x"):
        return flags[2:].zfill(5)  # p. ex.: remove "0x", zfill(5) -> "0001a"
    return flags.zfill(5)

def load_model(model_path):
    """Carrega o modelo do caminho especificado (arquivo .pkl)."""
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

def classify_packet(model, features):
    """Executa a predição com base nas features extraídas."""
    prediction = model.predict([features])
    return prediction[0]

############################################
# 4. LÓGICA DE DETECÇÃO EM THREAD
############################################
attack_flag = 0
attack_lock = threading.Lock()

def detection_thread_func(interface, capture_filter, model):
    """
    Captura pacotes em tempo real usando PyShark. Extrai as 3 features:
      - flags (após remover '0x')
      - time_delta
      - length
    Se o modelo retornar 'attack', define attack_flag=1; caso contrário, attack_flag=0.
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

                # Converte para tipos numéricos.
                # Se flags for estritamente decimal, use int(flags_str).
                # Se for hex, use int(flags_str, 16). Ajuste conforme seu modelo.
                flags_int = int(flags_str) 
                time_delta_f = float(time_delta)
                length_int = int(length)

                features = [flags_int, time_delta_f, length_int]

                prediction = classify_packet(model, features)
                logging.info(f"Classificação do pacote: {prediction}")

                # Ajustar logicamente se o modelo retornar "attack" ou outro valor.
                if str(prediction).lower() == "attack":
                    with attack_lock:
                        attack_flag = 1
                else:
                    with attack_lock:
                        attack_flag = 0

        except Exception as e:
            logging.error(f"Erro ao processar pacote: {e}")

############################################
# 5. LÓGICA DE CONTROLE DO SURICATA (THREAD)
############################################
def suricata_control_thread_func():
    """
    Loop que periodicamente lê a variável 'attack_flag'.
    - Se 1 (ataque), configura e inicia Suricata em IPS (se não estiver ativo).
    - Se 0, para Suricata e limpa iptables (se estiver ativo).
    """
    global attack_flag
    suricata_ativo = False

    logging.info("Thread de controle do Suricata iniciada.")
    while True:
        time.sleep(2)  # Verifica a cada 2 segundos

        with attack_lock:
            current_flag = attack_flag

        if current_flag == 1 and not suricata_ativo:
            logging.info("[SURICATA] Ataque detectado -> habilitando IPS.")
            configure_suricata_for_ips()
            start_suricata()
            suricata_ativo = True

        elif current_flag == 0 and suricata_ativo:
            logging.info("[SURICATA] Sem ataque -> parando Suricata e resetando iptables.")
            stop_suricata()
            reset_iptables()
            suricata_ativo = False

############################################
# 6. MANEJO DE SINAL / LIMPEZA
############################################
def handle_exit(signal_received, frame):
    logging.info("Recebido sinal de saída. Limpando iptables e parando Suricata...")
    stop_suricata()
    reset_iptables()
    sys.exit(0)

############################################
# 7. MAIN
############################################
def main():
    configure_logging()
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    logging.info("Iniciando script unificado (Detecção + Suricata).")

    # Verifica se Suricata está instalado
    check_suricata_installation()

    # Carrega o modelo de IA (ajuste o caminho se necessário)
    modelo_path = "/home/lab-iot03/Detector/ada_model.pkl"
    try:
        model = load_model(modelo_path)
        logging.info(f"Modelo IA carregado de: {modelo_path}")
    except Exception as e:
        logging.error(f"Erro ao carregar modelo: {e}")
        sys.exit(1)

    # Interface e filtro de captura
    interface = "wlo1"
    capture_filter = "tcp or mqtt"

    # Cria e inicia a thread de detecção
    detection_thread = threading.Thread(
        target=detection_thread_func,
        args=(interface, capture_filter, model),
        daemon=True
    )
    detection_thread.start()

    # Cria e inicia a thread de controle do Suricata
    suricata_thread = threading.Thread(
        target=suricata_control_thread_func,
        daemon=True
    )
    suricata_thread.start()

    # Mantém o script rodando até Ctrl+C
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
