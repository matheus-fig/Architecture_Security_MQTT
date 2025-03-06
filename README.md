# IoT Cybersecurity MQTT By Super

This project aims to detect denial-of-service (DoS) attacks in MQTT networks using packet capture and machine learning-based classification.

## 📌 Overview
The tool captures network packets in real-time, extracts relevant features, and uses a trained model to classify the packets. If an attack is detected, mitigation measures are automatically triggered, such as blocking MQTT packets via iptables and stopping the HiveMQ broker.

## 🛠️ Technologies Used
- **Python**: for packet capture and processing
- **PyShark**: library for packet capturing
- **Scikit-learn**: for the machine learning model
- **iptables**: for blocking MQTT packets
- **C++ (Arduino)**: for sensor firmware
- **HiveMQ**: MQTT broker used in the project

---

## 🚀 Features

### 1️⃣ Packet Capture and Processing
- Captures packets in real-time using PyShark
- Extracts relevant features for classification
- Preprocesses captured values
- Classifies packets using a trained model

### 2️⃣ Attack Detection and Mitigation
- Blocks MQTT packets via iptables
- Automatically stops the HiveMQ broker when an attack is detected

### 3️⃣ Communication with MQTT Sensors
- Uses ESP32 for temperature capture
- Publishes data to the HiveMQ broker
- Implements a moving average filter for stable readings

---

## 📂 Project Structure
```bash
📂 SUPER-IoT-Cybersecurity_MQTT
├── Plant_Code/
   ├── plant_2code.ino               # ESP32 firmware for temperature collection via MQTT
├── Security Architecture/
   ├── main.py                       # Main code for packet capture and attack detection
├── Training Machine Learning model/
│   ├── ada_model.pkl                # Trained model for packet classification
├── README.md                        # Project documentation
```

---

## 🔧 Setup and Execution

### 🖥️ Requirements
- Python 3.x
- Libraries: PyShark, Scikit-learn
- MQTT Broker (e.g., HiveMQ)
- ESP32 device with DHT11 sensor

### 🔹 Setup
1. **Install Python dependencies:**
```bash
pip install pyshark scikit-learn
```
2. **Run the detector:**
```bash
python main.py
```
3. **Upload the firmware to ESP32:**
   - Configure WiFi credentials and broker IP in `plant_2code.ino`
   - Compile and upload the code using Arduino IDE

---

## 📜 Code Explanation

### 🔹 `main.py` (Attack Detector)
- **Captures packets** in real-time using PyShark
- **Extracts features** such as TCP flags, time, and size
- **Classifies packets** with a trained model
- **Blocks MQTT packets** via iptables if an attack is detected
- **Stops the HiveMQ broker** when an attack is detected

### 🔹 `plant_2code.ino` (ESP32 Firmware)
- **Reads temperature** using a DHT11 sensor
- **Calculates a moving average** for stable readings
- **Sends data via MQTT** to the HiveMQ broker
- **Automatically reconnects** in case of failure

---

### 📬 Contact
If you have any questions or need support, please contact lucadias@super.ufam.edu.br or matheuscastro@super.ufam.edu.br
