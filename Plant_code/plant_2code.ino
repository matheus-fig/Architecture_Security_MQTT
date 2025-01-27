#include <Adafruit_Sensor.h>
#include <DHT.h>
#define DHT11_PIN  4
#define DHTTYPE DHT11 // tipo de dht
DHT dht(DHT11_PIN, DHTTYPE); // instancia do sensor

#include <WiFi.h>
#include <PubSubClient.h>

const char* ssid = "labiot01";        
const char* password = "acessomqtt";
const char* mqttServer = "10.42.0.1"; // Broker local (HiveMQ)
const int mqttPort = 1883;

// def dos topicos  
const char* mqtt_topic_temperatura = "sensor/temperatura"; // Tópico para temperatura

WiFiClient espClient;
PubSubClient client(espClient);

// Variáveis para controle de tempo com millis()
unsigned long lastSensorReadTime = 0; // Última leitura do sensor
unsigned long lastReconnectAttempt = 0; // Última tentativa de reconexão
const unsigned long sensorIntervalNormal = 60000; // Intervalo normal de leitura (60 segundos)
const unsigned long sensorIntervalInicial = 1000; // Intervalo inicial rápido (1 segundo)
unsigned long sensorInterval = sensorIntervalInicial; // Intervalo atual (começa com o inicial)
const unsigned long reconnectInterval = 5000; // Intervalo de tentativa de reconexão (5 segundos)

// Variáveis para a média móvel
const int numReadings = 5;            // Número de leituras para a média móvel
float readings[numReadings];          // Array para armazenar as leituras
int readIndex = 0;                    // Índice da leitura atual
float total = 0;                      // Soma das leituras
bool isArrayFilled = false;           // Indica se o array foi preenchido completamente

// conexao wifi
void setupWiFi() {
  Serial.println();
  Serial.print("Conectando ao WiFi...");
  WiFi.begin(ssid, password);

  unsigned long startAttemptTime = millis(); // Tempo inicial da tentativa de conexão

  while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 10000) {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Falha ao conectar ao WiFi!");
  } else {
    Serial.println("Conectado!");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
  }
}

// config mqtt
void reconnect() {
  Serial.print("Conectando ao MQTT...");
  if (client.connect("ESP32Client")) {
    Serial.println("Conectado!");
    client.subscribe(mqtt_topic_temperatura); // Inscreve no tópico de temperatura
  } else {
    Serial.print("Falha, rc=");
    Serial.print(client.state());
    Serial.println(" Tentando novamente em 5 segundos...");
  }
}

// Função para calcular a média móvel
float readFilteredTemperature() {
  float rawTemperature = dht.readTemperature(); // Lê o valor bruto do sensor

  if (isnan(rawTemperature)) {
    Serial.println("Falha ao ler do sensor DHT!");
    return NAN; // Retorna um valor inválido em caso de falha
  }

  // Adiciona a nova leitura ao array
  total -= readings[readIndex];       // Subtrai a leitura mais antiga
  readings[readIndex] = rawTemperature; // Armazena a nova leitura
  total += readings[readIndex];       // Adiciona a nova leitura
  readIndex = (readIndex + 1) % numReadings; // Avança o índice

  // Verifica se o array foi preenchido completamente
  if (!isArrayFilled && readIndex == 0) {
    isArrayFilled = true;
    sensorInterval = sensorIntervalNormal; // Altera para o intervalo normal
    Serial.println("Array de leituras preenchido. Mudando para intervalo normal.");
  }

  // Retorna a média móvel apenas se o array estiver completamente preenchido
  if (isArrayFilled) {
    return total / numReadings;
  } else {
    return NAN; // Retorna um valor inválido até que o array esteja cheio
  }
}

void setup() {
  // Inicializa o Serial
  Serial.begin(9600);
  delay(1000); // Aguarda 1 segundo para o Serial inicializar
  Serial.println("Inicializando...");

  // Inicializa o sensor DHT
  dht.begin();
  Serial.println("Sensor DHT inicializado.");

  // Conexão Wi-Fi
  setupWiFi();
  
  // Configura o cliente MQTT
  client.setServer(mqttServer, mqttPort);
  Serial.println("Cliente MQTT configurado.");

  // Inicializa o array de leituras para a média móvel
  for (int i = 0; i < numReadings; i++) {
    readings[i] = 0;
  }
}

void loop() {
  // Verifica a conexão MQTT e tenta reconectar se necessário
  if (!client.connected()) {
    unsigned long currentTime = millis();
    if (currentTime - lastReconnectAttempt >= reconnectInterval) {
      lastReconnectAttempt = currentTime;
      reconnect();
    }
  } else {
    client.loop(); // Mantém a conexão MQTT ativa
  }

  // Leitura do sensor no intervalo definido
  unsigned long currentTime = millis();
  if (currentTime - lastSensorReadTime >= sensorInterval) {
    lastSensorReadTime = currentTime; // Atualiza o tempo da última leitura

    // Leitura filtrada do sensor de temperatura
    float filteredTemperature = readFilteredTemperature();

    // Verifica se a leitura foi bem-sucedida
    if (isnan(filteredTemperature)) {
      Serial.println("Aguardando preenchimento do array de leituras...");
    } else {
      // Publicação no broker MQTT
      char temperaturaStr[8];
      dtostrf(filteredTemperature, 6, 2, temperaturaStr);
      Serial.print("Publicando temperatura: ");
      Serial.println(temperaturaStr);
      client.publish(mqtt_topic_temperatura, temperaturaStr);

      // Exibição no monitor serial
      Serial.print("Temperatura Filtrada: ");
      Serial.print(filteredTemperature);
      Serial.println(" °C");
    }
  }
}
