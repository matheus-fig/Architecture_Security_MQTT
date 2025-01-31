import pyshark
import pickle

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

        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

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