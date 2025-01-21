# pre processa e implementa o modelo de IA

import pyshark
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np
import pickle  # Usaremos joblib para carregar o modelo .pkl

# Define as features categóricas que devem usar Label Encoding
categorical_features = ['tcp.flags', 'mqtt.conack.flags', 'mqtt.conflag.cleansess', 'mqtt.conflags', 
                        'mqtt.dupflag', 'mqtt.hdrflags', 'mqtt.msg', 'mqtt.msgtype', 'mqtt.protoname']

# Features numéricas para normalização
numeric_features = ['tcp.flags', 'tcp.time_delta', 'tcp.len', 'mqtt.conack.flags',
       'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.dupflag',
       'mqtt.hdrflags', 'mqtt.kalive', 'mqtt.len', 'mqtt.msg', 'mqtt.msgid',
       'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.protoname', 'mqtt.qos',
       'mqtt.ver']

# Inicializa o Label Encoder para cada feature categórica
label_encoders = {feature: LabelEncoder() for feature in categorical_features}

# Inicializa o Standard Scaler para normalizar as features numéricas
scaler = StandardScaler()

# Função para ajustar classes dinamicamente para o LabelEncoder
def fit_label_encoder(encoder, value):
    # Ajusta o LabelEncoder e transforma o valor ao mesmo tempo
    return encoder.fit_transform([value])[0]  # Aplica fit_transform e retorna o valor codificado

def preprocess_value(value, feature_name):
    """
    Preprocessa o valor capturado. Substitui N/A por 0 e aplica Label Encoding para valores categóricos,
    e normalização para valores numéricos.

    Args:
        value: O valor capturado.
        feature_name: Nome da feature para aplicar o método correspondente (Label Encoding ou Normalização).

    Returns:
        O valor preprocessado.
    """
    if value == 'N/A' or value is None:
        return 0
    try:
        # Aplica Label Encoding se a feature for categórica
        if feature_name in categorical_features:
            encoder = label_encoders[feature_name]
            return fit_label_encoder(encoder, value)

        # Aplica normalização se a feature for numérica
        if feature_name in numeric_features:
            return float(value)

        return value
    except Exception as e:
        print(f"Erro ao processar {feature_name}: {e}")
        return value

def capture_and_preprocess(interface, capture_filter, model):
    """
    Captura pacotes TCP e MQTT, preprocessa os valores em tempo real, faz a classificação com o modelo e exibe os resultados.

    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'eth0').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
        model: O modelo de IA carregado a partir de um arquivo .pkl.
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)

    for packet in capture.sniff_continuously():
        print("\n--- Novo Pacote Capturado ---")
        try:
            # Extraindo e preprocessando os valores dos pacotes
            features = []

            # Preprocessa e extrai as informações da camada TCP
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                features.append(preprocess_value(tcp_layer.flags, 'tcp.flags'))
                features.append(preprocess_value(getattr(tcp_layer, 'time_delta', 'N/A'), 'tcp.time_delta'))
                features.append(preprocess_value(getattr(tcp_layer, 'len', 'N/A'), 'tcp.len'))

            # Preprocessa e extrai as informações da camada MQTT
            if 'MQTT' in packet:
                mqtt_layer = packet.mqtt
                features.append(preprocess_value(getattr(mqtt_layer, 'conack_flags', 'N/A'), 'mqtt.conack.flags'))
                features.append(preprocess_value(getattr(mqtt_layer, 'conflag_cleansess', 'N/A'), 'mqtt.conflag.cleansess'))
                features.append(preprocess_value(getattr(mqtt_layer, 'conflags', 'N/A'), 'mqtt.conflags'))
                features.append(preprocess_value(getattr(mqtt_layer, 'dupflag', 'N/A'), 'mqtt.dupflag'))
                features.append(preprocess_value(getattr(mqtt_layer, 'hdrflags', 'N/A'), 'mqtt.hdrflags'))
                features.append(preprocess_value(getattr(mqtt_layer, 'kalive', 'N/A'), 'mqtt.kalive'))
                features.append(preprocess_value(getattr(mqtt_layer, 'len', 'N/A'), 'mqtt.len'))
                features.append(preprocess_value(getattr(mqtt_layer, 'msg', 'N/A'), 'mqtt.msg'))
                features.append(preprocess_value(getattr(mqtt_layer, 'msgid', 'N/A'), 'mqtt.msgid'))
                features.append(preprocess_value(getattr(mqtt_layer, 'msgtype', 'N/A'), 'mqtt.msgtype'))
                features.append(preprocess_value(getattr(mqtt_layer, 'proto_len', 'N/A'), 'mqtt.proto_len'))
                features.append(preprocess_value(getattr(mqtt_layer, 'protoname', 'N/A'), 'mqtt.protoname'))
                features.append(preprocess_value(getattr(mqtt_layer, 'qos', 'N/A'), 'mqtt.qos'))
                features.append(preprocess_value(getattr(mqtt_layer, 'ver', 'N/A'), 'mqtt.ver'))

            # Normalizando as features numéricas
            features_normalized = scaler.fit_transform([features])[0]

            # Fazendo a previsão com o modelo carregado
            prediction = model.predict([features_normalized])

            print(f"Classificação do Pacote: {prediction[0]}")

        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    # Carregar o modelo salvo em .pkl (substitua o caminho pelo seu arquivo .pkl)
    with open("/home/lab-iot03/DoSDefender2/modelo/svm_model.pkl", "rb") as model_file:
        model = pickle.load(model_file)

    # Substitua 'eth0' pela interface de rede apropriada (ex.: 'wlan0' ou 'lo')
    interface = "wlo1"
    capture_filter = "tcp or mqtt"  # Filtro para pacotes TCP e MQTT

    print("Iniciando captura de pacotes e classificação com IA. Pressione Ctrl+C para parar.")
    try:
        capture_and_preprocess(interface, capture_filter, model)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nA captura e classificação foram finalizadas.")
