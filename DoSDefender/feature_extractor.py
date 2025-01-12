# feature_extractor.py

def extract_mqtt_features(scapy_pkt):
    """
    Dado um pacote Scapy com camada TCP/MQTT,
    extrai as features esperadas pelo modelo.
    Retorna uma lista ou numpy array com as colunas
    [tcp.flags, tcp.len, mqtt.msgtype, mqtt.len, ...] etc.
    """

    # Inicializar as features com algum valor default
    tcp_flags = 0
    tcp_len   = 0
    mqtt_msgtype = 0
    mqtt_len  = 0
    # etc.

    # Verificar se tem TCP
    if scapy_pkt.haslayer('TCP'):
        tcp_layer = scapy_pkt.getlayer('TCP')
        tcp_flags = tcp_layer.flags
        tcp_len   = len(tcp_layer.payload)  # ou scapy_pkt[TCP].len, depende do parse

    # Verificar se tem MQTT (Scapy decodifica como "MQTT" se for a porta 1883 por padrão)
    # Às vezes será reconhecido como Raw. Precisará forçar dissect se for porta customizada.
    if scapy_pkt.haslayer('MQTT'):
        mqtt_layer = scapy_pkt.getlayer('MQTT')
        # Exemplo de campos que podem aparecer:
        #   mqtt_layer.msgtype
        #   mqtt_layer.len
        #   mqtt_layer.msg
        #   mqtt_layer.msgid
        #   mqtt_layer.proto_len
        #   ...
        mqtt_msgtype = getattr(mqtt_layer, 'msgtype', 0)
        mqtt_len     = getattr(mqtt_layer, 'len', 0)
        # e assim por diante

    # Retorna no exato formato que o modelo espera
    return [tcp_flags, tcp_len, mqtt_msgtype, mqtt_len]
