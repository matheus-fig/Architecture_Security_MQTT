import pyshark
import pickle
import os

def block_mqtt_packets():
    """Adiciona regras ao iptables para bloquear pacotes MQTT."""
    os.system("iptables -A INPUT -p tcp --dport 1883 -m string --algo bm --string 'MQTT' -j DROP")
    os.system("iptables -A OUTPUT -p tcp --sport 1883 -m string --algo bm --string 'MQTT' -j DROP")
    print("Attack detected! MQTT packets blocked!")

    os.system("pkill -f hivemq.jar")
    print("HiveMQ broker stopped!")

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
        print("\n--- New Packet Captured ---")
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
                print(f"Package Classification: {prediction}")
                if prediction == 1:
                    block_mqtt_packets()
                    break

        except Exception as e:
            print(f"Erro ao processar pacote: {e}")



if __name__ == "__main__":
    interface = "wlo1"
    capture_filter = "tcp or mqtt"
    model_path = "/home/lab-iot03/Detector/ada_model.pkl"

    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        model = load_model(model_path)
        capture_and_preprocess(interface, capture_filter, model)
    except KeyboardInterrupt:
        print("\nCapture terminated by user.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nNetwork out of order")