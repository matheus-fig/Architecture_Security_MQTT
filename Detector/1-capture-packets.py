# le os pacotes sem pre processar

import pyshark

def capture_tcp_mqtt_packets(interface, capture_filter):
    """
    Captura pacotes TCP e MQTT em uma interface e extrai as features especificadas.

    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'eth0').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)

    for packet in capture.sniff_continuously():
        print("\n--- Novo Pacote Capturado ---")
        try:
            # Verifica se o pacote tem camada TCP
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                print(f"tcp.flags: {tcp_layer.flags}")
                print(f"tcp.time_delta: {getattr(tcp_layer, 'time_delta', 'N/A')}")
                print(f"tcp.len: {getattr(tcp_layer, 'len', 'N/A')}")

            # Verifica se o pacote tem camada MQTT
            if 'MQTT' in packet:
                mqtt_layer = packet.mqtt
                print(f"mqtt.conack.flags: {getattr(mqtt_layer, 'conack_flags', 'N/A')}")
                print(f"mqtt.conflag.cleansess: {getattr(mqtt_layer, 'conflag_cleansess', 'N/A')}")
                print(f"mqtt.conflags: {getattr(mqtt_layer, 'conflags', 'N/A')}")
                print(f"mqtt.dupflag: {getattr(mqtt_layer, 'dupflag', 'N/A')}")
                print(f"mqtt.hdrflags: {getattr(mqtt_layer, 'hdrflags', 'N/A')}")
                print(f"mqtt.kalive: {getattr(mqtt_layer, 'kalive', 'N/A')}")
                print(f"mqtt.len: {getattr(mqtt_layer, 'len', 'N/A')}")
                print(f"mqtt.msg: {getattr(mqtt_layer, 'msg', 'N/A')}")
                print(f"mqtt.msgid: {getattr(mqtt_layer, 'msgid', 'N/A')}")
                print(f"mqtt.msgtype: {getattr(mqtt_layer, 'msgtype', 'N/A')}")
                print(f"mqtt.proto_len: {getattr(mqtt_layer, 'proto_len', 'N/A')}")
                print(f"mqtt.protoname: {getattr(mqtt_layer, 'protoname', 'N/A')}")
                print(f"mqtt.qos: {getattr(mqtt_layer, 'qos', 'N/A')}")
                print(f"mqtt.ver: {getattr(mqtt_layer, 'ver', 'N/A')}")
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    # Substitua 'eth0' pela interface de rede apropriada (ex.: 'wlan0' ou 'lo')
    interface = "wlo1"
    capture_filter = "tcp or mqtt"  # Filtro para pacotes TCP e MQTT

    print("Iniciando captura de pacotes. Pressione Ctrl+C para parar.")
    try:
        capture_tcp_mqtt_packets(interface, capture_filter)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nA captura foi finalizada e os pacotes foram exibidos no terminal.")