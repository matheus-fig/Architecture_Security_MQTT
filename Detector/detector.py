import pickle
from sklearn.preprocessing import LabelEncoder
from scapy.all import sniff, IP, TCP, Raw
from scapy.layers.mqtt import MQTT
import numpy as np

label_encoder = LabelEncoder()

# modelo SVM treinado
with open('svm_model.pkl', 'rb') as file:
    svm_model = pickle.load(file)

# pré-processador (StandardScaler)
with open('scaler.pkl', 'rb') as file:
    scaler = pickle.load(file)

# codificador de variáveis categóricas (LabelEncoder)
with open('label_encoder.pkl', 'rb') as file:
    label_encoder = pickle.load(file)

# processamento de pacotes e extração de características
def process_packet(packet):
    try:
        if packet.haslayer(TCP) and packet.haslayer(MQTT):
            # features TCP
            tcp_flags = packet[TCP].flags
            tcp_time_delta = getattr(packet.time, 'delta', 0)
            tcp_len = len(packet[TCP].payload)
            
            # features MQTT
            mqtt_layer = packet[MQTT]
            features = {
                'tcp.flags': tcp_flags,
                'tcp.time_delta': tcp_time_delta,
                'tcp.len': tcp_len,
                'mqtt.conack.flags': getattr(mqtt_layer, 'CONACK.flags', 0),
                'mqtt.conflag.cleansess': getattr(mqtt_layer, 'CONFLAG.cleansess', 0),
                'mqtt.conflags': getattr(mqtt_layer, 'CONFLAG', 0),
                'mqtt.dupflag': getattr(mqtt_layer, 'DUPFLAG', 0),
                'mqtt.hdrflags': getattr(mqtt_layer, 'HDRFLAGS', 0),
                'mqtt.kalive': getattr(mqtt_layer, 'KALIVE', 0),
                'mqtt.len': getattr(mqtt_layer, 'LEN', 0),
                'mqtt.msg': getattr(mqtt_layer, 'MSG', 0),
                'mqtt.msgid': getattr(mqtt_layer, 'MSGID', 0),
                'mqtt.msgtype': getattr(mqtt_layer, 'MSGTYPE', 0),
                'mqtt.proto_len': getattr(mqtt_layer, 'PROTO_LEN', 0),
                'mqtt.protoname': getattr(mqtt_layer, 'PROTONAME', ''),
                'mqtt.qos': getattr(mqtt_layer, 'QOS', 0),
                'mqtt.ver': getattr(mqtt_layer, 'VER', 0),
            }

            # variáveis categóricas
            for col in categorical_columns:
                if col in features and isinstance(features[col], str):
                    features[col] = label_encoder.transform([features[col]])[0]

            return np.array(list(features.values()))
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")
    return None

# detecção ataques
def detect_attack(packet):
    features = process_packet(packet)
    if features is not None:
        # padronização
        features = scaler.transform([features])
        prediction = svm_model.predict(features)
        if prediction[0] == 1:
            print("Ataque detectado!")

# captura de pacotes
print("Capturando pacotes...")
sniff(filter="tcp port 1883", prn=detect_attack, store=False)