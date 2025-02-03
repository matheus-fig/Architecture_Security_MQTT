import pyshark
import pickle
import os
import sys
import signal
import time
import logging
import subprocess

# ==============================================================================================
# ABAIXO, CODIGO PARA O SURICARA
# ==============================================================================================

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

# ==============================================================================================
# SCRIPT DE DETECCAO
# ==============================================================================================

def preprocess_value(value):
    """
    Preprocessa o valor capturado, substituindo N/A por 0.

    Args:
        value: O valor capturado.

    Returns:
        O valor preprocessado.
    """
    return 0 if value == 'N/A' else value

def preprocess_flags(flags):
    """
    Remove o prefixo '0x' e mantém os dígitos restantes.

    Args:
        flags (str): Valor das flags TCP capturadas.

    Returns:
        str: Flags formatadas sem o prefixo '0x'.
    """
    if flags.startswith("0x"):
        return flags[2:].zfill(5)  # remove "0x"
    return flags.zfill(5)

def load_model(model_path):
    """

    Args:
        model_path (str): Caminho do arquivo do modelo.
    Returns:
        O modelo carregado.
    """
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

def classify_packet(model, features):
    """
    Args:
        model: O modelo de classificação carregado.
        features (list): Lista de características extraídas do pacote.

    Returns:
        Predição do modelo.
    """
    prediction = model.predict([features])
    return prediction[0]

def capture_and_preprocess(interface, capture_filter, model):
    """
    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'eth0').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
        model: modelo classificador.
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)

    for packet in capture.sniff_continuously():
        print("\n--- Novo Pacote Capturado ---")
        try:
            # pre processamento
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                flags = preprocess_flags(tcp_layer.flags)
                time_delta = preprocess_value(getattr(tcp_layer, 'time_delta', 'N/A'))
                length = preprocess_value(getattr(tcp_layer, 'len', 'N/A'))
                
                print(f"tcp.flags: {flags}")
                print(f"tcp.time_delta: {time_delta}")
                print(f"tcp.len: {length}")
                
                # classificacao do pacote
                features = [int(flags), float(time_delta), int(length)]
                prediction = classify_packet(model, features)
                print(f"Classificação do pacote: {prediction}")
                # abaixo, o que eu adicionei
                if prediction == 1:
                    logging.info("[SURICATA] Ataque detectado -> habilitando IPS.")
                    configure_suricata_for_ips()
                    start_suricata()
                    check_suricata_ips_mode()
                    suricata_ativo = True

        except Exception as e:
            print(f"Erro ao processar pacote: {e}")




# ====================================================================================
# AVAIXO, PRINCIPAL CÓDIGO
# ====================================================================================

if __name__ == "__main__":
    interface = "wlo1"
    capture_filter = "tcp or mqtt"
    model_path = "/home/lab-iot03/Detector/ada_model.pkl"

    print("Iniciando captura de pacotes com preprocessamento. Pressione Ctrl+C para parar.")
    try:
        model = load_model(model_path)
        capture_and_preprocess(interface, capture_filter, model)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nA captura e preprocessamento foram finalizados.")
