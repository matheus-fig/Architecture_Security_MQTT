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
# 2. FUNÇÕES DE VERIFICAÇÃO DO SURICATA
############################################
def check_suricata_installation():
    """Verifica se o Suricata está instalado."""
    try:
        subprocess.run(["suricata", "--build-info"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("Suricata está instalado.")
    except FileNotFoundError:
        logging.error("Suricata não está instalado. Por favor, instale-o antes de executar este script.")
        sys.exit(1)

def check_suricata_rules():
    """
    Executa o comando de teste do Suricata para verificar se as regras foram carregadas corretamente.
    Comando: sudo suricata -T -c /etc/suricata/suricata.yaml -v
    """
    logging.info("Verificando carregamento das regras do Suricata...")
    cmd = ["sudo", "suricata", "-T", "-c", "/etc/suricata/suricata.yaml", "-v"]
    try:
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout + result.stderr
        if "Configuration provided was successfully loaded. Exiting." in output:
            logging.info("Regras do Suricata carregadas com sucesso.")
            logging.debug(f"Saída do teste:\n{output}")
        else:
            logging.error("Falha no carregamento das regras do Suricata. Verifique a configuração:")
            logging.error(output)
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao executar o comando de teste do Suricata: {e}")
        sys.exit(1)

def check_suricata_ips_mode():
    """
    Verifica se o Suricata está configurado para modo IPS (NFQUEUE).
    Essa verificação é feita após o Suricata ter sido ativado.
    """
    logging.info("Verificando se o Suricata está configurado para modo IPS (NFQUEUE)...")
    suricata_config_path = "/etc/suricata/suricata.yaml"
    try:
        with open(suricata_config_path, "r") as file:
            config = file.read()
        if "- nfqueue" in config:
            logging.info("Suricata está configurado em modo IPS (NFQUEUE habilitado).")
        else:
            logging.error("Suricata não está configurado em modo IPS (NFQUEUE não encontrado no arquivo de configuração).")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Erro ao ler o arquivo de configuração do Suricata: {e}")
        sys.exit(1)

############################################
# 3. FUNÇÕES DE CONFIGURAÇÃO DO SURICATA (IPS)
############################################
def configure_suricata_for_ips():
    """Configura o Suricata para modo IPS utilizando NFQUEUE."""
    logging.info("Configurando o Suricata para modo IPS...")
    suricata_config_path = "/etc/suricata/suricata.yaml"
    try:
        with open(suricata_config_path, "r") as file:
            config = file.read()
        if "- nflog" in config:
            config = config.replace("- nflog", "- nfqueue")
        with open(suricata_config_path, "w") as file:
            file.write(config)
        logging.info(f"Arquivo {suricata_config_path} atualizado para habilitar o modo NFQUEUE.")
    except FileNotFoundError:
        logging.error(f"Arquivo de configuração {suricata_config_path} não encontrado.")
        sys.exit(1)

    try:
        logging.info("Configurando regras do iptables para NFQUEUE...")
        subprocess.run(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        subprocess.run(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("Regras do iptables configuradas com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Falha ao configurar regras do iptables: {e}")
        sys.exit(1)

def reset_iptables():
    """Restaura as regras do iptables para o padrão."""
    logging.info("Resetando as regras do iptables para o padrão...")
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("Regra INPUT removida com sucesso.")
    except subprocess.CalledProcessError:
        logging.warning("Regra INPUT não encontrada ou já removida.")
    try:
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        logging.info("Regra OUTPUT removida com sucesso.")
    except subprocess.CalledProcessError:
        logging.warning("Regra OUTPUT não encontrada ou já removida.")

def is_suricata_running():
    """Verifica se o Suricata já está em execução."""
    try:
        result = subprocess.run(["pgrep", "-f", "suricata"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return (result.returncode == 0)
    except Exception as e:
        logging.error(f"Erro ao verificar o status do Suricata: {e}")
        return False

def start_suricata():
    """Inicia o Suricata em modo IPS."""
    if is_suricata_running():
        logging.info("Suricata já está em execução. Pulando a inicialização.")
        return
    logging.info("Iniciando o Suricata em modo IPS...")
    try:
        subprocess.Popen(["suricata", "--af-packet", "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("Suricata iniciado com sucesso.")
    except FileNotFoundError:
        logging.error("Falha ao iniciar o Suricata. Certifique-se de que ele está instalado corretamente.")
        sys.exit(1)

def stop_suricata():
    """Encerra o Suricata."""
    if not is_suricata_running():
        logging.info("Suricata não está em execução. Pulando encerramento.")
        return
    logging.info("Parando o Suricata...")
    try:
        subprocess.run(["pkill", "-f", "suricata"], check=True)
        logging.info("Suricata parado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Falha ao parar o Suricata: {e}")

############################################
# 4. FUNÇÕES DE DETECÇÃO E CLASSIFICAÇÃO
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
    return prediction[0]

############################################
# 5. THREAD DE DETECÇÃO
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
    Se o modelo retornar "attack", define attack_flag=1; caso contrário, 0.
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
                    attack_flag = 1 if str(prediction).lower() == "attack" else 0
        except Exception as e:
            logging.error(f"Erro ao processar pacote: {e}")

############################################
# 6. THREAD DE CONTROLE DO SURICATA (IPS)
############################################
def suricata_control_thread_func():
    """
    Loop que verifica periodicamente a variável 'attack_flag'.
    Quando a flag for 1 e o Suricata ainda não estiver ativo, o script:
      - Configura o Suricata para IPS
      - Inicia o Suricata
      - Verifica se ele está configurado para IPS
    Uma vez ativado, o Suricata permanece ligado.
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
            check_suricata_ips_mode()
            suricata_ativo = True
        # Removemos a lógica de desligamento para manter o Suricata ligado uma vez ativado.

############################################
# 7. MANEJO DE SINAIS E LIMPEZA
############################################
def handle_exit(signal_received, frame):
    logging.info("Recebido sinal de saída. Limpando iptables e parando o Suricata...")
    stop_suricata()
    reset_iptables()
    sys.exit(0)

############################################
# 8. MAIN
############################################
def main():
    configure_logging()
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    logging.info("Iniciando script unificado (Detecção + Suricata).")
    check_suricata_installation()
    check_suricata_rules()
    # Note que não chamamos check_suricata_ips_mode() aqui, pois o Suricata ainda está em modo IDS (padrão)
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
    suricata_thread = threading.Thread(
        target=suricata_control_thread_func,
        daemon=True
    )
    suricata_thread.start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
