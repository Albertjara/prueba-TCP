import socket
import threading
import os
import time
import struct
import random 

# --- Configuración y Constantes ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432))
TIMEOUT_IN_SECONDS = 30 * 60 

# Mapeo para el Modo de Dispositivo (ID Adicional 0x33)
MODE_MAP = {
    0x00: "Modo Normal (Seguimiento Continuo)",
    0x01: "Modo de Ultra-larga duración (Ahorro de energía)",
    0x04: "Modo de Punto Residente (Ahorro de energía inteligente)",
}

# --- Funciones de Utilidad y Protocolo (Mantenidas por necesidad) ---

def unescape_jt808(data_bytes_with_delimiters):
    """Des-escapa los bytes de un mensaje JT/T 808."""
    if data_bytes_with_delimiters.startswith(b'\x7e') and data_bytes_with_delimiters.endswith(b'\x7e'):
        data_to_unescape = data_bytes_with_delimiters[1:-1]
    else:
        data_to_unescape = data_bytes_with_delimiters
    
    unescaped_bytes = bytearray()
    i = 0
    while i < len(data_to_unescape):
        if data_to_unescape[i] == 0x7d and i + 1 < len(data_to_unescape):
            next_byte = data_to_unescape[i+1]
            if next_byte == 0x01: unescaped_bytes.append(0x7d); i += 2
            elif next_byte == 0x02: unescaped_bytes.append(0x7e); i += 2
            else: unescaped_bytes.append(data_to_unescape[i]); i += 1
        else: unescaped_bytes.append(data_to_unescape[i]); i += 1
    return bytes(unescaped_bytes)

def escape_jt808(data_bytes):
    """Escapa los bytes de un mensaje JT/T 808 para su transmisión."""
    escaped = data_bytes.replace(b'\x7d', b'\x7d\x01')
    return b'\x7e' + escaped.replace(b'\x7e', b'\x7d\x02') + b'\x7e'

def create_jt808_packet(message_id, terminal_phone_number_raw, serial_number_raw, body):
    """Construye un paquete JT/T 808 completo."""
    body_length = len(body)
    # Se ajustan los atributos del cuerpo (Longitud en 10 bits, más bits de flags)
    message_body_attributes = (body_length & 0x03FF).to_bytes(2, 'big') 
    header = message_id.to_bytes(2, 'big') + message_body_attributes + terminal_phone_number_raw + serial_number_raw
    
    checksum_payload = header + body
    calculated_checksum = 0
    for byte in checksum_payload:
        calculated_checksum ^= byte
    
    raw_frame = checksum_payload + calculated_checksum.to_bytes(1, 'big')
    final_packet = escape_jt808(raw_frame)
    return final_packet, raw_frame.hex()

def parse_status_bits(status_raw):
    """Decodifica los 4 bytes de información de estado de posición básica."""
    status_int = int.from_bytes(status_raw, 'big')
    
    acc_status = "Encendido (ACC ON)" if (status_int & 0b1) == 1 else "Apagado (ACC OFF)"
    pos_status_std_alt = "Posicionado" if ((status_int >> 1) & 0b1) == 0 else "No Posicionado"
    latitude_type = "Sur (S)" if (status_int >> 29) & 0b1 else "Norte (N)" 
    longitude_type = "Oeste (W)" if (status_int >> 30) & 0b1 else "Este (E)" 
    encryption_status = "Cifrada" if (status_int >> 31) & 0b1 else "No Cifrada"

    return {
        "Estado ACC": acc_status,
        "Estado Posición": pos_status_std_alt,
        "Tipo Latitud": latitude_type,
        "Tipo Longitud": longitude_type,
        "Cifrado GPS": encryption_status,
        "Valor RAW Completo": hex(status_int)
    }

# --- Funciones de Decodificación de Información Adicional ---

def decode_mileage(value):
    """Decodifica el Kilometraje (ID 0x01)."""
    mileage_m = int.from_bytes(value, 'big')
    return f"**{mileage_m / 10.0:.1f} km**"

def decode_signal_strength(value):
    """Decodifica la Fuerza de Señal (ID 0x30)."""
    return f"**{int.from_bytes(value, 'big')}** (Nivel de señal)"

def decode_satellite_count(value):
    """Decodifica el Conteo de Satélites (ID 0x31)."""
    return f"**{int.from_bytes(value, 'big')}**"

def decode_movement_duration(value):
    """Decodifica la Duración de Movimiento (ID 0x32)."""
    if len(value) == 2:
        return f"**{int.from_bytes(value, 'big')} segundos**"
    return f"Valor RAW: {value.hex()} (Longitud inesperada)"

def decode_device_mode(value):
    """Decodifica el Modo de Dispositivo (ID 0x33)."""
    device_mode_int = int.from_bytes(value, 'big')
    mode_desc = MODE_MAP.get(device_mode_int, "Modo Desconocido")
    return f"**{mode_desc}** (Valor RAW: {device_mode_int})"

def decode_iccid(value):
    """Decodifica el ICCID (ID 0x00B2)."""
    return f"**{value.hex()}**"

def decode_extended_status(value):
    """Decodifica el Estado Propietario Extendido (ID 0x0089)."""
    if len(value) == 4:
        status_int = int.from_bytes(value, 'big')
        # Lógica simplificada de bits propietarios
        sleep_status = "Dormido" if (status_int & 0b1) == 1 else "Activo"
        lift_status = "**LEVANTADO (Alarma)**" if (status_int >> 6) & 0b1 else "Normal (No Levantado)"
        return f"(RAW: {hex(status_int)}) | Suspensión: {sleep_status} | Levantamiento: {lift_status}"
    return f"Longitud inesperada de {len(value)} bytes."

def decode_extended_alarm(value):
    """Decodifica el Estado de Alarma Extendido (ID 0x00C5)."""
    if len(value) == 4:
        status_ext_int = int.from_bytes(value, 'big')
        pos_bits = (status_ext_int >> 3) & 0b11
        pos_status = {0b10: "GPS", 0b01: "Wi-Fi", 0b11: "GPS y Wi-Fi"}.get(pos_bits, "Sin Posicionamiento")
        
        vibration_bit = (status_ext_int >> 6) & 0b1
        vibration_status = "Normal" if vibration_bit == 1 else "**ALARMA DE VIBRACIÓN**"
        
        return f"(RAW: {hex(status_ext_int)}) | Posicionamiento: {pos_status} | Vibración: {vibration_status}"
    return f"Longitud inesperada de {len(value)} bytes."

def decode_voltage(value):
    """Decodifica el Voltaje (ID 0x002D)."""
    if len(value) == 2:
        voltage_mv = int.from_bytes(value, 'big') 
        return f"**{voltage_mv / 1000.0:.3f} V**"
    return f"Longitud inesperada de {len(value)} bytes."

def decode_battery_level(value):
    """Decodifica el Porcentaje de Batería (ID 0x00A8)."""
    if len(value) == 1:
        return f"**{value[0]} %**"
    return f"Longitud inesperada de {len(value)} bytes."

def decode_imei(value):
    """Decodifica el IMEI (ID 0x00D5)."""
    try:
        return value[:15].decode('ascii', errors='ignore').strip('\x00')
    except Exception:
        return f"ERROR (RAW: {value.hex()})"

def decode_wifi_data(value):
    """Decodifica la información de Wi-Fi (ID 0x00B9)."""
    if not value: return "Datos de Wi-Fi vacíos."
    
    try:
        count = value[0]
        wifi_data_string = value[1:].decode('ascii', errors='ignore').strip('\x00').strip()
        
        # El patrón es MAC,RSSI,MAC,RSSI,... 
        wifi_entries = [e for e in wifi_data_string.split(',') if e]
        output = [f"Contador de redes Wi-Fi: {count}"]
        
        for i in range(0, len(wifi_entries), 2):
            if i + 1 < len(wifi_entries):
                mac = wifi_entries[i]
                rssi = wifi_entries[i+1]
                output.append(f"  > MAC: {mac}, RSSI (dBm): {rssi}")
        
        return "\n".join(output)
    except Exception as e:
        return f"[ERROR] Fallo en decodificación Wi-Fi: {e}"

def decode_unknown_placeholder(value):
    """Función de marcador de posición para IDs no documentados (como 0x000C)."""
    return f"Valor binario (Longitud: {len(value)}): {value.hex()}"


# Diccionario de mapeo de IDs de Información Adicional a funciones de decodificación
ADDITIONAL_INFO_DECODERS = {
    # Estándar JT/T 808 (1 byte ID)
    0x01: ("Kilometraje", decode_mileage),
    0x30: ("Fuerza de Señal", decode_signal_strength),
    0x31: ("Conteo de Satélites", decode_satellite_count),
    0x32: ("Duración de Movimiento", decode_movement_duration),
    0x33: ("Modo de Dispositivo", decode_device_mode),
    
    # Propietario (2 bytes ID: 0x00XX)
    0x000C: ("Placeholder Desconocido (0x000C)", decode_unknown_placeholder), 
    0x00B2: ("ICCID", decode_iccid),
    0x0089: ("Estado Propietario Extendido", decode_extended_status),
    0x00C5: ("Estado de Alarma Extendido", decode_extended_alarm),
    0x002D: ("Voltaje (mV)", decode_voltage),
    0x00A8: ("Porcentaje de Batería", decode_battery_level),
    0x00D5: ("IMEI", decode_imei),
    0x00B9: ("Redes Wi-Fi Encontradas", decode_wifi_data),
}

# --- Funciones de Comandos y Respuestas ---

def build_set_parameters_command(phone_number_raw, current_serial_number):
    """Construye un comando 0x8103 (Establecer Parámetros)."""
    COMMAND_ID = 0x8103
    
    # Parámetros de ejemplo: Intervalo de subida (0x0027) y Umbral de bajo voltaje (0x0045)
    param_id_27, param_len_27, param_value_27 = 0x0027, 0x04, 60 # 60 segundos
    param_id_45, param_len_45, param_value_45 = 0x0045, 0x04, struct.pack('>f', 3.5) # 3.5 V
    
    body_payload = b'\x02' # Conteo de Parámetros (N=2)
    # Parámetro 1: Intervalo de subida
    body_payload += param_id_27.to_bytes(4, 'big') + param_len_27.to_bytes(1, 'big') + param_value_27.to_bytes(4, 'big')
    # Parámetro 2: Umbral de bajo voltaje
    body_payload += param_id_45.to_bytes(4, 'big') + param_len_45.to_bytes(1, 'big') + param_value_45
    
    command_serial_raw = ((current_serial_number + 1) % 65536).to_bytes(2, 'big')
    print("\n    -> [COMANDO] Preparando comando de Establecer Parámetros (0x8103)...")
    
    final_packet, raw_frame_hex = create_jt808_packet(COMMAND_ID, phone_number_raw, command_serial_raw, body_payload)
    print(f"    -> [COMANDO 0x8103] RAW: {raw_frame_hex}")
    return final_packet, command_serial_raw, raw_frame_hex, COMMAND_ID

def build_query_parameters_command(phone_number_raw, current_serial_number):
    """Construye un comando 0x8104 (Consulta de Parámetros de Terminal)."""
    COMMAND_ID = 0x8104
    # Consultamos solo los parámetros que establecimos para evitar saturación
    params_to_query = [0x0027, 0x0045] 
    
    body_payload = len(params_to_query).to_bytes(1, 'big')
    for param_id in params_to_query:
        body_payload += param_id.to_bytes(4, 'big')
    
    command_serial_raw = ((current_serial_number + 2) % 65536).to_bytes(2, 'big')
    print("\n    -> [COMANDO] Preparando comando de Consulta de Parámetros (0x8104)...")

    final_packet, raw_frame_hex = create_jt808_packet(COMMAND_ID, phone_number_raw, command_serial_raw, body_payload)
    print(f"    -> [COMANDO 0x8104] RAW: {raw_frame_hex}")
    return final_packet, command_serial_raw, raw_frame_hex, COMMAND_ID

def parse_query_parameters_response(message_body):
    """Decodifica el cuerpo del mensaje 0x0104 (Respuesta de parámetros de terminal de consulta)."""
    if len(message_body) < 3:
        print("    [ERROR] Cuerpo demasiado corto para respuesta de parámetros.")
        return

    original_serial, param_count = int.from_bytes(message_body[0:2], 'big'), message_body[2]
    print(f"  --- DECODIFICANDO RESPUESTA DE PARÁMETROS (0x0104) ---")
    print(f"    - Serial de Consulta Original: {original_serial} | Conteo: {param_count}")

    current_byte = 3
    for i in range(param_count):
        if current_byte + 5 > len(message_body): break
            
        param_id_raw = message_body[current_byte:current_byte+4]
        param_length = message_body[current_byte+4]
        param_id = int.from_bytes(param_id_raw, 'big')
        
        value_start, value_end = current_byte + 5, current_byte + 5 + param_length
        if value_end > len(message_body): break
            
        param_value_raw = message_body[value_start:value_end]
        display_value = param_value_raw.hex()
        
        # --- Lógica de Decodificación de Parámetros ---
        desc = "Valor RAW"

        if param_id == 0x0001 and param_length == 4:
            display_value = f"**{int.from_bytes(param_value_raw, 'big')} segundos** (Intervalo de reportes GPS)"
            desc = "GPS Reporting Interval"
        elif param_id == 0x0027 and param_length == 4:
            display_value = f"**{int.from_bytes(param_value_raw, 'big')} segundos** (Intervalo de subida)"
            desc = "Upload Interval"
        elif param_id == 0x0045 and param_length == 4:
            display_value = f"**{struct.unpack('>f', param_value_raw)[0]:.2f} V** (Umbral de bajo voltaje)"
            desc = "Low Voltage Threshold"
        elif param_id == 0x0010: 
            desc = "APN (Access Point Name)"
            try: display_value = f"**{param_value_raw.decode('ascii', errors='ignore').strip('\x00')}**"
            except: pass
        elif param_id == 0x0013: 
            desc = "Dirección de Servidor Principal"
            try: display_value = f"**{param_value_raw.decode('ascii', errors='ignore').strip('\x00')}**"
            except: pass
        elif param_id == 0x0011 or param_id == 0x0012: 
            desc = "Usuario/Contraseña APN"
            try: display_value = f"**{param_value_raw.decode('ascii', errors='ignore').strip('\x00')}**"
            except: pass
        elif param_id == 0x0083 and param_length == 8:
            desc = "ID Propietario (d4c14238...)"

        
        print(f"    - Parámetro {i+1} | ID: {hex(param_id)} | Longitud: {param_length} | Valor: {display_value} ({desc})")
        current_byte = value_end

# --- Lógica Principal de Decodificación de Posición (0x0200) ---

def parse_additional_info(message_body, additional_info_start):
    """Extrae y decodifica la información adicional del cuerpo 0x0200,
    manejando IDs de 1 y 2 bytes según la especificación JT/T 808 extendida."""
    current_byte = additional_info_start
    output = []
    
    while current_byte < len(message_body):
        
        additional_id = None
        additional_length = None
        header_size = 0

        # --- Intento 1: ID de 2 bytes (JT/T 808 Extended: 0x00XX) ---
        if current_byte + 3 <= len(message_body) and message_body[current_byte] == 0x00:
            additional_id = int.from_bytes(message_body[current_byte:current_byte+2], 'big')
            additional_length = message_body[current_byte+2]
            header_size = 3 # ID(2) + Length(1)
        
        # --- Intento 2: ID de 1 byte (JT/T 808 Standard) ---
        elif current_byte + 2 <= len(message_body):
            additional_id = message_body[current_byte]
            # Solo los IDs de 1 byte (0x01 a 0x7E) son válidos aquí
            if additional_id >= 0x80:
                 output.append(f"    [ERROR] ID de 1 byte ({hex(additional_id)}) fuera del rango esperado.")
                 break
            additional_length = message_body[current_byte+1]
            header_size = 2 # ID(1) + Length(1)
        
        # --- Datos insuficientes ---
        else:
            output.append(f"    [AVISO] Datos insuficientes para leer el siguiente ID/Longitud. Posición: {current_byte}.")
            break

        # Proceso de decodificación
        if additional_id is not None:
            
            # Ajustamos el puntero para saltar el encabezado
            current_byte += header_size
            
            start_value, end_value = current_byte, current_byte + additional_length
            
            if end_value > len(message_body): 
                output.append(f"    [ERROR] Longitud de valor ({additional_length}) para ID {hex(additional_id)} excede el cuerpo. Rompiendo ciclo.")
                break
            
            additional_value = message_body[start_value:end_value]
            current_byte = end_value # Avanzar al siguiente campo

            # Búsqueda y ejecución de decodificador en el diccionario
            decoder_tuple = ADDITIONAL_INFO_DECODERS.get(additional_id)
            if decoder_tuple:
                desc, decoder_func = decoder_tuple
                decoded_value = decoder_func(additional_value)
                output.append(f"  - ID {hex(additional_id)} ({desc}): {decoded_value}")
            else:
                output.append(f"  - ID {hex(additional_id)} (No Mapeado): RAW: {additional_value.hex()}")
        else:
            output.append(f"    [ERROR] No se pudo determinar el ID/Longitud en la posición {current_byte}. Deteniendo el parsing.")
            break


    return "\n".join(output)

# --- Función para Manejar Cada Cliente Conectado ---
def handle_client(conn, addr):
    """Maneja la conexión con el cliente, parseando mensajes JT/T 808 y enviando respuestas."""
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)
    last_terminal_serial, terminal_phone_number_raw = 0, None
    commands_to_send = [] 

    try:
        while True:
            data = conn.recv(1024)
            if not data: break
            
            # 1. Des-escape y Validación
            processed_data = unescape_jt808(data)
            checksum_received = processed_data[-1]
            payload_for_checksum = processed_data[:-1]
            
            calculated_checksum = 0
            for byte in payload_for_checksum: calculated_checksum ^= byte
            
            if calculated_checksum != checksum_received:
                print(f"  [ERROR] Checksum INCORRECTO ({checksum_received} != {calculated_checksum}). Descartando mensaje.")
                continue

            # 2. Parseo de Cabecera
            message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
            body_length = int.from_bytes(payload_for_checksum[2:4], 'big') & 0x03FF
            terminal_phone_number_raw = payload_for_checksum[4:10] 
            message_serial_number_raw = payload_for_checksum[10:12]
            message_body = payload_for_checksum[12:12 + body_length]

            message_serial_number = int.from_bytes(message_serial_number_raw, 'big')
            # Siempre actualizamos el último serial recibido del terminal
            last_terminal_serial = message_serial_number
            
            print(f"\n[DATOS RECIBIDOS de {addr}] (ID: {hex(message_id)}, Serial: {message_serial_number})")

            # 3. Lógica de Respuesta/Comando
            response_message_id, response_result, response_body = None, 0x00, b''

            if message_id == 0x0100: # REGISTRO
                response_message_id = 0x8100 
                response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + b"AUTH_CODE_BSJ_2025"
                # Activamos comandos al registrarse (SOLO UNA VEZ)
                commands_to_send = ['SET_PARAMS', 'QUERY_PARAMS']
            
            elif message_id == 0x0102: # AUTENTICACIÓN
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
                # Activamos comandos al autenticarse (SOLO UNA VEZ)
                commands_to_send = ['SET_PARAMS', 'QUERY_PARAMS']

            elif message_id == 0x0200: # REPORTE DE POSICIÓN
                
                # ... (Información Básica)
                status_data = parse_status_bits(message_body[4:8])
                latitude = int.from_bytes(message_body[8:12], 'big') / 1_000_000.0
                longitude = int.from_bytes(message_body[12:16], 'big') / 1_000_000.0
                time_raw = message_body[22:28] 
                time_str = f"20{time_raw[0]:02x}-{time_raw[1]:02x}-{time_raw[2]:02x} {time_raw[3]:02x}:{time_raw[4]:02x}:{time_raw[5]:02x} (UTC+8)"

                print("  --- INFORMACIÓN DE POSICIÓN BÁSICA (0x0200) ---")
                print(f"  - Lat/Lon: {latitude:.6f} ({status_data['Tipo Latitud']}) / {longitude:.6ff} ({status_data['Tipo Longitud']})")
                print(f"  - Estado: {status_data['Estado Posición']} | ACC: {status_data['Estado ACC']}")
                print(f"  - Hora del Reporte: {time_str}")
                
                # Información Adicional (Corregido)
                print("  --- INFORMACIÓN ADICIONAL DEL CUERPO ---")
                print(parse_additional_info(message_body, 28))
                print("  --- FIN DE INFORMACIÓN ADICIONAL ---")
                
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0104: # RESPUESTA DE PARÁMETROS
                # Decodificamos la respuesta de 17 parámetros que vimos en la consola
                parse_query_parameters_response(message_body)
                response_message_id = None # No se envía ACK después de 0x0104

            # Manejo del ACK Universal (0x0001) para comandos anteriores
            elif message_id == 0x0001:
                # El cuerpo es (ACK Serial Number | ACK Message ID | Result Code)
                ack_serial = int.from_bytes(message_body[0:2], 'big')
                ack_id = hex(int.from_bytes(message_body[2:4], 'big'))
                ack_result = message_body[4]
                result_str = "Éxito (0x00)" if ack_result == 0x00 else f"Fallo ({hex(ack_result)})"
                print(f"  [ACK UNIVERSAL] Confirmación para Serial: {ack_serial}, ID: {ack_id}. Resultado: {result_str}")
                response_message_id = None # No se envía ACK después de 0x0001


            # 4. Envío de Respuesta ACK
            if response_message_id and terminal_phone_number_raw:
                final_response, raw_frame_hex = create_jt808_packet(response_message_id, terminal_phone_number_raw, message_serial_number_raw, response_body)
                conn.sendall(final_response)
                print(f"    <- [ACK {hex(response_message_id)}] Enviado respuesta a Serial {message_serial_number}.")

            # 5. Envío de Comandos Pendientes (FIX: Solo si 'commands_to_send' fue seteado y luego se limpia)
            if commands_to_send and terminal_phone_number_raw:
                current_serial = last_terminal_serial
                
                for command_name in commands_to_send:
                    if command_name == 'SET_PARAMS':
                        packet, serial_raw, raw_hex, id = build_set_parameters_command(terminal_phone_number_raw, current_serial)
                        conn.sendall(packet)
                        # Usamos el serial del comando como base para el siguiente comando/paquete
                        current_serial = int.from_bytes(serial_raw, 'big')
                        
                    elif command_name == 'QUERY_PARAMS':
                        packet, serial_raw, raw_hex, id = build_query_parameters_command(terminal_phone_number_raw, current_serial)
                        conn.sendall(packet)
                        current_serial = int.from_bytes(serial_raw, 'big')

                # FIX CRÍTICO: Limpiar la lista para evitar el bucle infinito de comandos
                commands_to_send = []
                last_terminal_serial = current_serial # Actualizar el serial del terminal con el último serial de comando enviado
                
    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE] {e}")
    finally:
        conn.close()

# --- Punto de Entrada del Programa ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")

if __name__ == "__main__":
    start_server()
