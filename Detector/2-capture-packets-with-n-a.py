# lê e pre processa os valores N/A

import pyshark

def preprocess_value(value):
    """
    Preprocessa o valor capturado, substituindo N/A por 0.

    Args:
        value: O valor capturado.

    Returns:
        O valor preprocessado.
    """
    return 0 if value == 'N/A' else value

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
                print(f"tcp.flags: {preprocess_value(tcp_layer.flags)}")
                print(f"tcp.time_delta: {preprocess_value(getattr(tcp_layer, 'time_delta', 'N/A'))}")
                print(f"tcp.len: {preprocess_value(getattr(tcp_layer, 'len', 'N/A'))}")

            # Preprocessa e exibe as informações da camada MQTT
            if 'MQTT' in packet:
                mqtt_layer = packet.mqtt
                print(f"mqtt.conack.flags: {preprocess_value(getattr(mqtt_layer, 'conack_flags', 'N/A'))}")
                print(f"mqtt.conflag.cleansess: {preprocess_value(getattr(mqtt_layer, 'conflag_cleansess', 'N/A'))}")
                print(f"mqtt.conflags: {preprocess_value(getattr(mqtt_layer, 'conflags', 'N/A'))}")
                print(f"mqtt.dupflag: {preprocess_value(getattr(mqtt_layer, 'dupflag', 'N/A'))}")
                print(f"mqtt.hdrflags: {preprocess_value(getattr(mqtt_layer, 'hdrflags', 'N/A'))}")
                print(f"mqtt.kalive: {preprocess_value(getattr(mqtt_layer, 'kalive', 'N/A'))}")
                print(f"mqtt.len: {preprocess_value(getattr(mqtt_layer, 'len', 'N/A'))}")
                print(f"mqtt.msg: {preprocess_value(getattr(mqtt_layer, 'msg', 'N/A'))}")
                print(f"mqtt.msgid: {preprocess_value(getattr(mqtt_layer, 'msgid', 'N/A'))}")
                print(f"mqtt.msgtype: {preprocess_value(getattr(mqtt_layer, 'msgtype', 'N/A'))}")
                print(f"mqtt.proto_len: {preprocess_value(getattr(mqtt_layer, 'proto_len', 'N/A'))}")
                print(f"mqtt.protoname: {preprocess_value(getattr(mqtt_layer, 'protoname', 'N/A'))}")
                print(f"mqtt.qos: {preprocess_value(getattr(mqtt_layer, 'qos', 'N/A'))}")
                print(f"mqtt.ver: {preprocess_value(getattr(mqtt_layer, 'ver', 'N/A'))}")
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
