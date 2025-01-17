import pickle
import numpy as np
from sklearn.preprocessing import LabelEncoder
import paho.mqtt.client as mqtt

label_encoder = LabelEncoder()

# Carregar modelo SVM treinado
with open('svm_model.pkl', 'rb') as file:
    svm_model = pickle.load(file)

# Carregar pré-processador (StandardScaler)
with open('scaler.pkl', 'rb') as file:
    scaler = pickle.load(file)

# Função para identificar e processar variáveis categóricas e numéricas
def process_features(features):
    try:
        # Iterando pelas variáveis/features
        for col in features:
            # Verificando se o valor é uma string (categórica)
            if isinstance(features[col], str):
                # Se for categórica, treina o LabelEncoder e transforma a variável
                features[col] = label_encoder.fit_transform([features[col]])[0]
            elif isinstance(features[col], (int, float)):
                # Se for numérica, pode continuar normalmente (sem transformação)
                continue
            else:
                print(f"Tipo de dado não reconhecido para a coluna {col}: {features[col]}")
        return np.array(list(features.values()))
    except Exception as e:
        print(f"Erro ao processar as características: {e}")
    return None


# Função de processamento de pacotes MQTT
def on_message(client, userdata, msg):
    try:
        # Extraia características do payload MQTT
        mqtt_msg = msg.payload.decode()
        
        # Aqui você pode definir a extração de características a partir de `mqtt_msg`
        features = {
            'mqtt.msg': len(mqtt_msg),  # Exemplo simples: tamanho da mensagem MQTT
            # Adicione mais características conforme necessário
        }

        # Transformar variáveis categóricas
        for col in features:
            if isinstance(features[col], str):
                features[col] = label_encoder.transform([features[col]])[0]

        # Transformar em um array numpy
        feature_array = np.array(list(features.values())).reshape(1, -1)

        # Realizar a previsão
        feature_array = scaler.transform(feature_array)
        prediction = svm_model.predict(feature_array)
        if prediction[0] == 1:
            print("Ataque detectado!")
    except Exception as e:
        print(f"Erro ao processar a mensagem MQTT: {e}")

# Configurar cliente MQTT
client = mqtt.Client()
client.on_message = on_message

# Conectar ao broker MQTT (supondo que o broker esteja no localhost)
client.connect("10.42.0.1", 1883, 60)

# Inscrever-se no tópico MQTT
client.subscribe("your/topic")

# Loop para escutar mensagens MQTT
print("Aguardando mensagens MQTT...")
client.loop_forever()
