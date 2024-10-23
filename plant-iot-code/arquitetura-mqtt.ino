// Código para o funcionamento da planta IoT do projeto de ciberseguraça
// Comunicação MQTT
// Projeto SUPER - UFAM

// sensor de umidade
#include <DHT.h>
#define DHT11_PIN  32
#define DHTTYPE DHT11 // tipo de dht
DHT dht(DHT11_PIN, DHTTYPE); // instancia do sensor

// sensor ultrassonico - distancia
#include <Ultrasonic.h> 
const int PINO_TRIG = 14;
const int PINO_ECHO = 25; 
Ultrasonic ultrasonic(PINO_TRIG, PINO_ECHO); // instaciacao do obj

// LED
#define LED 33

// wifi
#include <WiFi.h> // para conectar na mesma rede do broker

// MQTT
#include <PubSubClient.h>

// Configurações da rede Wi-Fi
const char* ssid = "MQTT";
const char* password = "mqttpass";

// Configurações do broker MQTT
const char* mqtt_server = "192.168.137.1"; // IP do broker MQTT

// definicao dos topicos
const char* mqtt_topic_distancia = "sensor/distancia";
const char* mqtt_topic_umidade = "sensor/umidade";
const char* mqtt_topic_temperatura = "sensor/temperatura";
const char* mqtt_topic_led = "led/mensagem";

// Cliente Wi-Fi e MQTT
WiFiClient espClient;
PubSubClient client(espClient);

// ====================================================================================

// funcao de reconexao com o broker
void reconnect() {
  while (!client.connected()) {
    Serial.print("Tentando conectar ao broker MQTT...");
    if (client.connect("ESP32Client")) {
      Serial.println("Conectado ao broker MQTT!");
      
    } else {
      Serial.print("Falha ao conectar. Código de erro: ");
      Serial.print(client.state());
      Serial.println(" Tentando novamente em 5 segundos...");
      
      // Espera 5 segundos antes de tentar reconectar
      delay(5000);
    }
  }
}

// =============================================================

// funcao para acender-desligar o led
void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Mensagem recebida no tópico: ");
  Serial.println(topic);
  // condicao se a mensagem é para o topico do led 
  if (strcmp(topic, mqtt_topic_led) == 0) {
    if ((char)payload[0] == '1') {
      digitalWrite(LED, HIGH); // Acende o LED
      Serial.println("LED ligado!");
    } else if ((char)payload[0] == '0') {
      digitalWrite(LED, LOW); // Apaga o LED
      Serial.println("LED desligado!");
    }
  }
}

// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(1000);

    // sensor dht
    dht.begin();

    // LED
    pinMode(LED, OUTPUT);
    
    // conexao wifi
    Serial.println("Conectando ao Wi-Fi...");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Tentando conectar...");
    }
    Serial.println("Wi-Fi conectado!");
    Serial.print("Endereço IP: ");
    Serial.println(WiFi.localIP());

    // conexao com o broker
    client.setServer(mqtt_server, 1883);
    reconnect();
}

// ============================================================================

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Wi-Fi desconectado. Tentando reconectar...");
        WiFi.begin(ssid, password);
    } else {
        Serial.println("Wi-Fi está conectado.");
    }

  // mqtt
  if (!client.connected()) {
      reconnect();
  }
  client.loop();

  // leitura do sensor de distancia
  float distancia_float = ultrasonic.distanceRead(CM);
  Serial.print("Distância: ");
  Serial.print(distancia_float);
  Serial.println(" cm");

  // temp e umidade
  float umidade = dht.readHumidity();
  float temperatura = dht.readTemperature();

  if (isnan(umidade) || isnan(temperatura)) {
  Serial.println("Falha ao ler do sensor DHT!");
  } else {
    
  }
  // Publicacao - umidade e temperatura no broker MQTT
  char umidadeStr[8];
  dtostrf(umidade, 6, 2, umidadeStr);
  client.publish(mqtt_topic_umidade, umidadeStr);

  char temperaturaStr[8];
  dtostrf(temperatura, 6, 2, temperaturaStr);
  client.publish(mqtt_topic_temperatura, temperaturaStr);

  Serial.print("Umidade: ");
  Serial.print(umidade);
  Serial.println(" %");
    
  Serial.print("Temperatura: ");
  Serial.print(temperatura);
  Serial.println(" °C");

  // publicacao - distancia
  char distancia[50];
  dtostrf(distancia_float, 6, 2, distancia);
  client.publish(mqtt_topic_distancia, distancia);

  delay(2000);
}
