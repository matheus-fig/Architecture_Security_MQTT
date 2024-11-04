// Código da arquitetura do projeto de ciberseguraça
// Comunicação MQTT
// Projeto SUPER - UFAM

// sensor de umidade
#include <Adafruit_Sensor.h>
#include <DHT.h>
#define DHT11_PIN  4
#define DHTTYPE DHT11 // tipo de dht
DHT dht(DHT11_PIN, DHTTYPE); // instancia do sensor

// sensor ultrassonico - distancia
#include <Ultrasonic.h> 
const int PINO_TRIG = 14;
const int PINO_ECHO = 25; 
Ultrasonic ultrasonic(PINO_TRIG, PINO_ECHO); // instaciacao do obj

#include <WiFi.h>
#include <PubSubClient.h>

const char* ssid = "MQTT";        
const char* password = "mqttpass";
const char* mqttServer = "192.168.137.1"; // broker ip
const int mqttPort = 1883;

// def dos topicos
const char* topic = "led/controle";
const char* mqtt_topic_distancia = "sensor/distancia";
const char* mqtt_topic_umidade = "sensor/umidade";
const char* mqtt_topic_temperatura = "sensor/temperatura";  

WiFiClient espClient;
PubSubClient client(espClient);

const int ledPin = 2;

// funcao para ligar-desligar o led
void callback(char* topic, byte* payload, unsigned int length) {
  String message;
  for (int i = 0; i < length; i++) {
    message += (char)payload[i];
  }
  if (message == "1") {
    digitalWrite(ledPin, HIGH);
  } else if (message == "0") {
    digitalWrite(ledPin, LOW);
  }
}

// conexao wifi
void setupWiFi() {
  delay(10);
  Serial.println();
  Serial.print("Conectando ao WiFi...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  
  Serial.println("Conectado!");
}

// config mqtt
void reconnect() {
  while (!client.connected()) {
    Serial.print("Conectando ao MQTT...");
    if (client.connect("ESP32Client")) {
      Serial.println("Conectado!");
      client.subscribe(topic);
    } else {
      Serial.print("Falha, rc=");
      Serial.print(client.state());
      Serial.println(" Tentando novamente em 5 segundos...");
      delay(5000);
    }
  }
}

void setup() {
  
  // sensor dht
  dht.begin();

  // led
  pinMode(ledPin, OUTPUT);

  
  Serial.begin(9600);

  // conexao wifi
  setupWiFi();
  
  client.setServer(mqttServer, mqttPort);
  client.setCallback(callback);
}

void loop() {
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
  // publicacao - umidade e temperatura no broker MQTT
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
