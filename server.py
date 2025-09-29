import socket
import threading
import os
import time
import struct

# --- Configuración del Servidor ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432))
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

# --- Mapeo de Valores a Descripciones ---

# Mapeo para el Modo de Dispositivo (ID Adicional 0x33)
MODE_MAP = {
    0x00: "Modo Normal (Seguimiento Continuo)",
    0x01: "Modo de Ultra-larga duración (Ahorro de energía)",
    # Añadir otros modos si se descubren
}

# Mapeo para el Bit de Posicionamiento (dentro de Status/Estado)
POS_BIT_MAP = {
    0: "Sin Posicionamiento",
    1: "Posicionamiento GPS (Bit 1)",
    2: "Posicionamiento Wi-Fi (Bit 2)",
    3: "Posicionamiento GPS y Wi-Fi"
}

# Mapeo para el Estado de Carga (dentro de 0x00C5 en 0xEB, bit 2)
CHARGING_STATUS_MAP = {
    0: "No Cargando (Descargando o Batería)",
    1: "Cargando (Conectado a fuente de alimentación)",
}

# --- Función para Des-escapar Bytes JT/T 808 ---
def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808 (elimina 0x7d 0x01 -> 0x7d y 0x7d 0x02 -> 0x7e).
    """
    if data_bytes_with_delimiters.startswith(b'\x7e') and \
       data_bytes_with_delimiters.endswith(b'\x7e'):
        data_to_unescape = data_bytes_with_delimiters[1:-1]
    else:
        data_to_unescape = data_bytes_with_delimiters

    unescaped_bytes = bytearray()
    i = 0
    while i < len(data_to_unescape):
        if data_to_unescape[i] == 0x7d:
            if i + 1 < len(data_to_unescape):
                if data_to_unescape[i+1] == 0x01:
                    unescaped_bytes.append(0x7d)
                    i += 2
                elif data_to_unescape[i+1] == 0x02:
                    unescaped_bytes.append(0x7e)
                    i += 2
                else:
                    unescaped_bytes.append(data_to_unescape[i])
                    i += 1
            else:
                unescaped_bytes.append(data_to_unescape[i])
                i += 1
        else:
            unescaped_bytes.append(data_to_unescape[i])
            i += 1
    return bytes(unescaped_bytes)

# --- Función para interpretar los bits de estado de posición (4 bytes) ---
def parse_status_bits(status_raw):
    """
    Decodifica los 4 bytes de información de estado de posición (Byte 4-8 del cuerpo 0x0200).
    """
    status_int = int.from_bytes(status_raw, 'big')
    
    # Extraemos el estado de posicionamiento (Bits 1 y 2)
    pos_bits = (status_int >> 1) & 0b11
    pos_status = POS_BIT_MAP.get(pos_bits, "Tipo de posicionamiento Desconocido")

    # Extraemos el bit de ACC (Bit 0)
    acc_status = "Encendido (ACC ON)" if (status_int & 0b1) == 1 else "Apagado (ACC OFF)"
    
    # Ejemplo de otros bits estándar (JT/T 808):
    latitude_type = "Sur (S)" if (status_int >> 2) & 0b1 else "Norte (N)"
    longitude_type = "Oeste (W)" if (status_int >> 3) & 0b1 else "Este (E)"

    return {
        "Raw Hex": status_raw.hex(),
        "Estado ACC": acc_status,
        "Posicionamiento": pos_status,
        "Tipo Latitud": latitude_type,
        "Tipo Longitud": longitude_type,
        "Bits Desconocidos/Reservados": hex(status_int >> 4) # Mostramos el resto
    }

# --- Función para parsear sub-campos de la trama extendida 0xEB ---
def parse_extended_eb_fields(additional_value):
    """
    Analiza la sub-trama extendida (ID 0xeb).
    Utiliza el formato propietario: Longitud de Bloque (2 bytes) + ID (2 bytes) + Valor (N bytes).
    """
    sub_data = additional_value
    
    # Saltamos el encabezado inicial '000c00' (3 bytes)
    sub_current_byte = 3 
    
    print("    - INICIO DE DECODIFICACIÓN DETALLADA DE 0xEB:")
    
    while sub_current_byte < len(sub_data):
        # 1. Leer Longitud del Bloque (2 bytes)
        if sub_current_byte + 2 > len(sub_data):
            break
            
        sub_length_block = int.from_bytes(sub_data[sub_current_byte:sub_current_byte+2], 'big')

        # 2. Leer ID del Bloque (2 bytes)
        id_start = sub_current_byte + 2
        sub_id = int.from_bytes(sub_data[id_start:id_start+2], 'big')
        
        # 3. Calcular Longitud y Bytes del Valor
        value_start = id_start + 2
        value_length = sub_length_block - 2 
        value_end = value_start + value_length

        if value_end > len(sub_data):
            print(f"      [ERROR] Longitud de valor inválida para el campo {hex(sub_id)}. Posición actual: {sub_current_byte}")
            break
            
        sub_value_bytes = sub_data[value_start:value_end]
        
        print(f"      > Campo ID: {hex(sub_id)} | Longitud Valor: {value_length} bytes | HEX: {sub_value_bytes.hex()}")

        if sub_id == 0x002D: # Voltaje (2 bytes, mV)
            if value_length == 2:
                voltage_mv = int.from_bytes(sub_value_bytes, 'big')
                voltage_v = voltage_mv / 1000.0
                print(f"        -> **Voltaje del Dispositivo**: {voltage_v:.3f} V (Valor RAW: {voltage_mv} mV)")

        elif sub_id == 0x00A8: # Porcentaje de Batería (1 byte)
            if value_length == 1:
                percentage = sub_value_bytes[0]
                print(f"        -> **Porcentaje de Batería**: {percentage} %")
        
        elif sub_id == 0x00D5: # Número IMEI (15 bytes ASCII)
            if value_length == 15:
                try:
                    imei = sub_value_bytes.decode('ascii')
                    print(f"        -> **IMEI del Dispositivo**: {imei}")
                except UnicodeDecodeError:
                    print(f"        -> IMEI (Error de decodificación): {sub_value_bytes.hex()}")

        elif sub_id == 0x00C5: # Estado de Alarma Extendido (4 bytes)
            if value_length == 4:
                status_ext_int = int.from_bytes(sub_value_bytes, 'big')
                # Bit 2 (0x4): Carga/Alimentación (0: No Cargando, 1: Cargando)
                charging_bit = (status_ext_int >> 2) & 0b1
                charging_status = CHARGING_STATUS_MAP.get(charging_bit, "Desconocido")
                
                print(f"        -> **Estado de Carga/Alimentación**: {charging_status}")
                # Bit 6 (0x40): Alarma de Vibración (1: Normal, 0: Alarma) - No está claro en la documentación si es invertido.
                vibration_bit = (status_ext_int >> 6) & 0b1
                vibration_status = "Normal (No Vibración)" if vibration_bit == 1 else "Alarma de Vibración"
                print(f"        -> Estado de Vibración (Bit 6): {vibration_status}")

        elif sub_id == 0x00B9: # Información de Wi-Fi
            try:
                wifi_data_string = sub_value_bytes.decode('ascii')
                wifi_entries = wifi_data_string.split(',')
                print(f"        -> **Redes Wi-Fi Encontradas** ({len(wifi_entries)//2} pares MAC, RSSI):")
                for i in range(0, len(wifi_entries), 2):
                    if i + 1 < len(wifi_entries):
                        mac = wifi_entries[i]
                        rssi = wifi_entries[i+1]
                        print(f"          > MAC: {mac}, RSSI (dBm): {rssi}")
            except (UnicodeDecodeError, IndexError):
                print(f"        -> Error de decodificación de datos Wi-Fi.")
        
        elif sub_id == 0x00B2: # ICCID
            iccid = sub_value_bytes.hex()
            print(f"        -> **ICCID de la SIM**: {iccid}")

        else:
            print(f"        -> [Campo Desconocido]: {sub_value_bytes.hex()}")
        
        sub_current_byte = value_end
        
    print("    - FIN DE DECODIFICACIÓN DETALLADA DE 0xEB.")


# --- Función para Manejar Cada Cliente Conectado ---
def handle_client(conn, addr):
    """
    Maneja la conexión con el cliente, parseando mensajes y enviando respuestas.
    """
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)

    try:
        while True:
            data = conn.recv(1024)

            if not data:
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado.")
                break
            
            # 1. Des-escapar y Validar Checksum
            processed_data = unescape_jt808(data)
            
            print(f"\n[DATOS RECIBIDOS de {addr}] (Hex Crudo: {data.hex()})")
            print(f"[DATOS PROCESADOS de {addr}] (Hex Des-escapado: {processed_data.hex()})")

            if len(processed_data) < 13: 
                print(f"[ERROR] Datos demasiado cortos para un mensaje válido.")
                continue

            checksum_received = processed_data[-1]
            payload_for_checksum = processed_data[:-1]

            calculated_checksum = 0
            for byte in payload_for_checksum:
                calculated_checksum ^= byte
            
            if calculated_checksum == checksum_received:
                print(f"  [DEBUG] Checksum OK: {hex(checksum_received)}")
            else:
                print(f"  [ERROR] Checksum INCORRECTO. Recibido: {hex(checksum_received)}, Calculado: {hex(calculated_checksum)}. Descartando mensaje.")
                continue

            # 2. Parsear Cabecera del Mensaje
            if len(payload_for_checksum) < 12:
                print(f"[ERROR] Payload demasiado corto para la cabecera.")
                continue

            message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
            message_body_attributes = int.from_bytes(payload_for_checksum[2:4], 'big')
            terminal_phone_number_raw = payload_for_checksum[4:10]
            message_serial_number_raw = payload_for_checksum[10:12]

            body_length = message_body_attributes & 0x03FF 
            message_body = payload_for_checksum[12:12 + body_length]

            terminal_phone_number_str = terminal_phone_number_raw.hex()
            message_serial_number = int.from_bytes(message_serial_number_raw, 'big')

            print(f"  --> ID Mensaje: {hex(message_id)}")
            print(f"  --> Teléfono Terminal (BCD): {terminal_phone_number_str}")
            print(f"  --> Número de Serie (Trama): {message_serial_number}")
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # 3. Lógica de Respuesta
            response_message_id = None
            response_result = 0x00 # 0x00 = Éxito, 0x01 = Fallo, etc.
            response_body = b''

            if message_id == 0x0100: 
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100) - INICIANDO LOGIN")
                
                # Campos de Registro (Cuerpo 0x0100): Provincia (2), Ciudad (2), Fabricante (5 ASCII), Modelo (20 ASCII), ID Terminal (7 bytes BCD)
                manufacturer_id = message_body[4:9].decode('ascii')
                model_terminal = message_body[9:29].decode('ascii').strip('\x00')
                
                print(f"    - ID Fabricante: {manufacturer_id}, Modelo: {model_terminal}")

                response_message_id = 0x8100 # Respuesta de registro de terminal
                auth_code = b"AUTH_CODE_BSJ_2025" # Código de autenticación
                
                # Cuerpo 0x8100: Serial (2) + Resultado (1) + Código Autenticación (N)
                response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + auth_code
                print(f"    -> [RESPUESTA] Envío de Código de Autenticación: {auth_code.decode()}")

            elif message_id == 0x0102:
                print("  --> Tipo de Mensaje: AUTENTICACIÓN DE TERMINAL (0x0102)")
                # Si el terminal se autentica, respondemos con el reconocimiento general
                
                response_message_id = 0x8001
                # Cuerpo 0x8001: Serial (2) + ID Mensaje Recibido (2) + Resultado (1)
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0200: 
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200) - DECODIFICANDO DATOS")
                
                # 0x0200: Alarma (4) + Estado (4) + Latitud (4) + Longitud (4) + Altitud (2) + Velocidad (2) + Dirección (2) + Hora (6) + Info Adicional (N)
                if len(message_body) < 28:
                    response_result = 0x01
                    print("    [ERROR] Cuerpo de posición demasiado corto.")
                else:
                    # Decodificación de información básica
                    status_raw = message_body[4:8]
                    status_data = parse_status_bits(status_raw)

                    latitude_raw = int.from_bytes(message_body[8:12], 'big')
                    longitude_raw = int.from_bytes(message_body[12:16], 'big')
                    time_raw = message_body[22:28]
                    
                    latitude = latitude_raw / 1_000_000.0
                    longitude = longitude_raw / 1_000_000.0
                    time_str = f"20{time_raw[0]:02x}-{time_raw[1]:02x}-{time_raw[2]:02x} {time_raw[3]:02x}:{time_raw[4]:02x}:{time_raw[5]:02x} GMT+8"
                    
                    print("  --- Información de Posición Básica ---")
                    print(f"  - Posicionamiento: **{status_data['Posicionamiento']}**")
                    print(f"  - Estado del ACC: {status_data['Estado ACC']}")
                    print(f"  - Latitud: {latitude:.6f} ({status_data['Tipo Latitud']})")
                    print(f"  - Longitud: {longitude:.6f} ({status_data['Tipo Longitud']})")
                    print(f"  - Hora (UTC+8): {time_str}")

                    # --- ANÁLISIS DE LA INFORMACIÓN ADICIONAL (ID 1 byte) ---
                    additional_info_start = 28
                    if len(message_body) > additional_info_start:
                        print("  --- Información Adicional del Cuerpo (ID 1 byte) ---")
                        current_byte = additional_info_start
                        while current_byte < len(message_body):
                            if current_byte + 2 > len(message_body): break

                            additional_id = message_body[current_byte]
                            additional_length = message_body[current_byte+1]
                            
                            start_value = current_byte + 2
                            end_value = start_value + additional_length
                            
                            if end_value > len(message_body): break
                            
                            additional_value = message_body[start_value:end_value]
                            
                            print(f"  - ID Adicional: {hex(additional_id)} | Longitud: {additional_length}")
                            
                            if additional_id == 0x33: # Modo de dispositivo (ID 0x33)
                                device_mode_int = int.from_bytes(additional_value, 'big')
                                mode_desc = MODE_MAP.get(device_mode_int, "Modo Desconocido")
                                print(f"    -> Modo de Trabajo: **{mode_desc}** (Valor RAW: {device_mode_int})")
                            
                            elif additional_id == 0x30: # Fuerza de señal
                                signal_strength = int.from_bytes(additional_value, 'big')
                                print(f"    -> Fuerza de señal inalámbrica: {signal_strength}")

                            elif additional_id == 0xeb:
                                # Llamamos a la función dedicada para decodificar la trama extendida
                                parse_extended_eb_fields(additional_value)
                            
                            else:
                                print(f"    -> ID {hex(additional_id)} (No Mapeado): {additional_value.hex()}")
                            
                            current_byte = end_value 
                
                # Reconocimiento general para el reporte de posición
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}. No se requiere respuesta.")
            
            # 4. Construcción y Envío de la Respuesta
            if response_message_id:
                response_body_len = len(response_body)
                response_attributes = (response_body_len & 0x03FF).to_bytes(2, 'big')
                
                response_header = response_message_id.to_bytes(2, 'big') + \
                                  response_attributes + \
                                  terminal_phone_number_raw + \
                                  message_serial_number_raw

                checksum_response_payload = response_header + response_body
                calculated_response_checksum = 0
                for byte in checksum_response_payload:
                    calculated_response_checksum ^= byte
                
                final_response_raw = checksum_response_payload + calculated_response_checksum.to_bytes(1, 'big')
                # La respuesta también debe ser escapada y delimitada por 0x7e
                final_response = b'\x7e' + final_response_raw + b'\x7e'

                conn.sendall(final_response)
                print(f"  [RESPUESTA ENVIADA a {addr}] Mensaje {hex(response_message_id)} con serial {message_serial_number} y resultado {response_result}.")
                print(f"  Respuesta completa (Hex): {final_response.hex()}")

    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE] Problema con cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")

# --- Función para Iniciar el Servidor Principal ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start()
            
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")
    finally:
        server_socket.close()
        print("Servidor TCP detenido.")

# --- Punto de Entrada del Programa ---
if __name__ == "__main__":
    start_server()
