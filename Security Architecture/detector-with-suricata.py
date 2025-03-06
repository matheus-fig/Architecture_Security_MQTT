import pyshark
import pickle
import os

def block_mqtt_packets():
    """Adds rules to iptables to block MQTT packets."""
    
    os.system("iptables -A INPUT -p tcp --dport 1883 -m string --algo bm --string 'MQTT' -j DROP")
    os.system("iptables -A OUTPUT -p tcp --sport 1883 -m string --algo bm --string 'MQTT' -j DROP")
    print("MQTT packets successfully blocked.")

def preprocess_value(value):
     """
    Preprocesses the captured value, replacing N/A with 0.

    Args:
        value: The captured value.

    Returns:
        The preprocessed value.
    """
    
    return 0 if value == 'N/A' else value

def preprocess_flags(flags):
    """
    Removes the '0x' prefix and keeps the remaining digits.

    Args:
        flags (str): Captured TCP flags value.

    Returns:
        str: Formatted flags without the '0x' prefix.
    """
    
    if flags.startswith("0x"):
        return flags[2:].zfill(5)
    return flags.zfill(5)

def load_model(model_path):
    """
    Loads the classification model from a file.

    Args:
        model_path (str): Path to the model file.

    Returns:
        The loaded model.
    """
    
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

def classify_packet(model, features):
    """
    Classifies a network packet using the provided model.

    Args:
        model: The loaded classification model.
        features (list): List of extracted packet features.

    Returns:
        Model prediction.
    """
    
    prediction = model.predict([features])
    return prediction[0]

def capture_and_preprocess(interface, capture_filter, model):
    """
    Captures and preprocesses network packets for classification.

    Args:
        interface (str): Network interface name for packet capture (e.g., 'eth0').
        capture_filter (str): Capture filter (e.g., 'tcp or mqtt').
        model: The classification model.
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
                print(f"Classificação do pacote: {prediction}")
                if prediction == 1:
                    os.system('systemctl start suricata.service')
                    break

        except Exception as e:
            print(f"Erro ao processar pacote: {e}")



if __name__ == "__main__":
    interface = "wlo1"
    capture_filter = "tcp or mqtt"
    model_path = "/home/lab-iot03/Detector/ada_model.pkl"

    print("Starting packet capture with preprocessing. Press Ctrl+C to stop.")
    try:
        model = load_model(model_path)
        capture_and_preprocess(interface, capture_filter, model)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nPacket capture and preprocessing completed.")
