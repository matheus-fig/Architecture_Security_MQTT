# pre processa aplicando Label Encoder

import pyshark
from sklearn.preprocessing import LabelEncoder
import numpy as np

# Define as features categóricas que devem usar Label Encoding
categorical_features = ['tcp.flags', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 
                        'mqtt.dupflag', 'mqtt.hdrflags', 'mqtt.msg', 'mqtt.msgtype', 'mqtt.protoname']

# Inicializa o Label Encoder para cada feature categórica
label_encoders = {feature: LabelEncoder() for feature in categorical_features}

# Função para ajustar classes dinamicamente para o LabelEncoder
def fit_label_encoder(encoder, value):
    # Ajusta o LabelEncoder e transforma o valor ao mesmo tempo
    return encoder.fit_transform([value])[0]  # Aplica fit_transform e retorna o valor codificado

def preprocess_value(value, feature_name):
    """
    Preprocessa o valor capturado. Substitui N/A por 0 e aplica Label Encoding para valores categóricos.

    Args:
        value: O valor capturado.
        feature_name: Nome da feature para aplicar Label Encoding (se necessário).

    Returns:
        O valor preprocessado.
    """
    if value == 'N/A':
        return 0
    try:
        # Aplica Label Encoding se a feature for categórica
        if feature_name in categorical_features:
            encoder = label_encoders[feature_name]

            # Ajusta o Label Encoder dinamicamente
            return fit_label_encoder(encoder, value)

        return value
    except Exception as e:
        print(f"Erro ao codificar {feature_name}: {e}")
        return value

def capture_and_preprocess(interface, capture_filter):
    """
    Captura pacotes TCP e MQTT, preprocessa os valores em tempo real e exibe os resultados.

    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'eth0').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)

    for packet in capture.sniff_continuously():
        print("\n--- Novo Pacote Capturado ---")
        try:
            # Preprocessa e exibe as informações da camada TCP
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                print(f"tcp.flags: {preprocess_value(tcp_layer.flags, 'tcp.flags')}")
                print(f"tcp.time_delta: {preprocess_value(getattr(tcp_layer, 'time_delta', 'N/A'), 'tcp.time_delta')}")
                print(f"tcp.len: {preprocess_value(getattr(tcp_layer, 'len', 'N/A'), 'tcp.len')}")

            # Preprocessa e exibe as informações da camada MQTT
            if 'MQTT' in packet:
                mqtt_layer = packet.mqtt
                print(f"mqtt.conack.flags: {preprocess_value(getattr(mqtt_layer, 'conack_flags', 'N/A'), 'mqtt.conack.flags')}")
                print(f"mqtt.conflag.cleansess: {preprocess_value(getattr(mqtt_layer, 'conflag_cleansess', 'N/A'), 'mqtt.conflag.cleansess')}")
                print(f"mqtt.conflags: {preprocess_value(getattr(mqtt_layer, 'conflags', 'N/A'), 'mqtt.conflags')}")
                print(f"mqtt.dupflag: {preprocess_value(getattr(mqtt_layer, 'dupflag', 'N/A'), 'mqtt.dupflag')}")
                print(f"mqtt.hdrflags: {preprocess_value(getattr(mqtt_layer, 'hdrflags', 'N/A'), 'mqtt.hdrflags')}")
                print(f"mqtt.kalive: {preprocess_value(getattr(mqtt_layer, 'kalive', 'N/A'), 'mqtt.kalive')}")
                print(f"mqtt.len: {preprocess_value(getattr(mqtt_layer, 'len', 'N/A'), 'mqtt.len')}")
                print(f"mqtt.msg: {preprocess_value(getattr(mqtt_layer, 'msg', 'N/A'), 'mqtt.msg')}")
                print(f"mqtt.msgid: {preprocess_value(getattr(mqtt_layer, 'msgid', 'N/A'), 'mqtt.msgid')}")
                print(f"mqtt.msgtype: {preprocess_value(getattr(mqtt_layer, 'msgtype', 'N/A'), 'mqtt.msgtype')}")
                print(f"mqtt.proto_len: {preprocess_value(getattr(mqtt_layer, 'proto_len', 'N/A'), 'mqtt.proto_len')}")
                print(f"mqtt.protoname: {preprocess_value(getattr(mqtt_layer, 'protoname', 'N/A'), 'mqtt.protoname')}")
                print(f"mqtt.qos: {preprocess_value(getattr(mqtt_layer, 'qos', 'N/A'), 'mqtt.qos')}")
                print(f"mqtt.ver: {preprocess_value(getattr(mqtt_layer, 'ver', 'N/A'), 'mqtt.ver')}")
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    # Substitua 'eth0' pela interface de rede apropriada (ex.: 'wlan0' ou 'lo')
    interface = "wlo1"
    capture_filter = "tcp or mqtt"  # Filtro para pacotes TCP e MQTT

    print("Iniciando captura de pacotes com preprocessamento. Pressione Ctrl+C para parar.")
    try:
        capture_and_preprocess(interface, capture_filter)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nA captura e preprocessamento foram finalizados.")


