"""
feature_extractor.py

Contém a função de extração das 17 features necessárias para
o modelo de classificação de ataques MQTT DoS.
"""

# IMPORTS
from scapy.all import TCP

# Caso esteja usando scapy.contrib.mqtt, importe:
# from scapy.contrib.mqtt import MQTT

# Variável global para calcular tcp.time_delta de pacotes consecutivos
# (se precisar de algo por fluxo específico, mude a lógica)
previous_packet_time = None

def extract_mqtt_features(scapy_pkt):
    """
    Extrai as seguintes 17 features (em exata ordem):
    1) 'tcp.flags'
    2) 'tcp.time_delta'
    3) 'tcp.len'
    4) 'mqtt.conack.flags'
    5) 'mqtt.conflag.cleansess'
    6) 'mqtt.conflags'
    7) 'mqtt.dupflag'
    8) 'mqtt.hdrflags'
    9) 'mqtt.kalive'
    10) 'mqtt.len'
    11) 'mqtt.msg'
    12) 'mqtt.msgid'
    13) 'mqtt.msgtype'
    14) 'mqtt.proto_len'
    15) 'mqtt.protoname'
    16) 'mqtt.qos'
    17) 'mqtt.ver'

    Parâmetros:
        scapy_pkt: Pacote do Scapy (camada IP, TCP, MQTT)

    Retorna:
        Uma lista com 17 elementos, na ordem acima.
    """

    global previous_packet_time

    # -------------------------------------------
    # 1) tcp.time_delta
    # -------------------------------------------
    if previous_packet_time is None:
        # Primeiro pacote, não há delta
        tcp_time_delta = 0.0
    else:
        tcp_time_delta = scapy_pkt.time - previous_packet_time

    previous_packet_time = scapy_pkt.time

    # -------------------------------------------
    # 2) tcp.flags, tcp.len
    # -------------------------------------------
    tcp_flags = 0
    tcp_len   = 0

    if scapy_pkt.haslayer(TCP):
        tcp_layer = scapy_pkt.getlayer(TCP)

        # tcp.flags (inteiro com bits combinados, ex: 2=SYN, 4=RST, etc.)
        tcp_flags = getattr(tcp_layer, 'flags', 0)

        # Não há "tcp.len" nativo no Scapy. Podemos estimar via payload:
        tcp_payload = tcp_layer.payload
        tcp_len = len(bytes(tcp_payload)) if tcp_payload else 0

    # -------------------------------------------
    # 3) Campos MQTT
    # -------------------------------------------
    mqtt_conack_flags = 0
    mqtt_conflag_cleansess = 0
    mqtt_conflags = 0
    mqtt_dupflag = 0
    mqtt_hdrflags = 0
    mqtt_kalive = 0
    mqtt_len_ = 0   # Para não conflitar com tcp_len
    mqtt_msg = 0
    mqtt_msgid = 0
    mqtt_msgtype = 0
    mqtt_proto_len = 0
    mqtt_protoname = ""  # pode ser string
    mqtt_qos = 0
    mqtt_ver = 0

    # Verifica se a camada MQTT está presente
    # Se o scapy_pkt não estiver decodificando como MQTT, pode vir como Raw.
    # Você pode forçar dissect ou filtrar pela porta 1883.
    if hasattr(scapy_pkt, 'haslayer') and scapy_pkt.haslayer("MQTT"):
        mqtt_layer = scapy_pkt.getlayer("MQTT")

        mqtt_conack_flags      = getattr(mqtt_layer, 'conack_flags', 0)
        mqtt_conflag_cleansess = getattr(mqtt_layer, 'conflag_cleansess', 0)
        mqtt_conflags          = getattr(mqtt_layer, 'conflags', 0)
        mqtt_dupflag           = getattr(mqtt_layer, 'dupflag', 0)
        mqtt_hdrflags          = getattr(mqtt_layer, 'hdrflags', 0)
        mqtt_kalive            = getattr(mqtt_layer, 'kalive', 0)
        mqtt_len_              = getattr(mqtt_layer, 'len', 0)
        mqtt_msg               = getattr(mqtt_layer, 'msg', 0)
        mqtt_msgid             = getattr(mqtt_layer, 'msgid', 0)
        mqtt_msgtype           = getattr(mqtt_layer, 'msgtype', 0)
        mqtt_proto_len         = getattr(mqtt_layer, 'proto_len', 0)
        mqtt_protoname         = getattr(mqtt_layer, 'protoname', "")
        mqtt_qos               = getattr(mqtt_layer, 'qos', 0)
        mqtt_ver               = getattr(mqtt_layer, 'ver', 0)

    # -------------------------------------------
    # Montar a lista final na ordem exata
    # -------------------------------------------
    features = [
        tcp_flags,               # 'tcp.flags'
        tcp_time_delta,          # 'tcp.time_delta'
        tcp_len,                 # 'tcp.len'
        mqtt_conack_flags,       # 'mqtt.conack.flags'
        mqtt_conflag_cleansess,  # 'mqtt.conflag.cleansess'
        mqtt_conflags,           # 'mqtt.conflags'
        mqtt_dupflag,            # 'mqtt.dupflag'
        mqtt_hdrflags,           # 'mqtt.hdrflags'
        mqtt_kalive,             # 'mqtt.kalive'
        mqtt_len_,               # 'mqtt.len'
        mqtt_msg,                # 'mqtt.msg'
        mqtt_msgid,              # 'mqtt.msgid'
        mqtt_msgtype,            # 'mqtt.msgtype'
        mqtt_proto_len,          # 'mqtt.proto_len'
        mqtt_protoname,          # 'mqtt.protoname'
        mqtt_qos,                # 'mqtt.qos'
        mqtt_ver                 # 'mqtt.ver'
    ]

    return features
