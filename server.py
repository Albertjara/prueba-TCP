import socket
import threading
import os
import time
from datetime import datetime

# --- Configuración y Constantes ---
# El servidor escuchará en todas las interfaces (0.0.0.0)
HOST = '0.0.0.0'
# El puerto por defecto es 5432, configurable mediante la variable de entorno 'PORT'
PORT = int(os.environ.get('PORT', 5432))
# Tiempo de espera antes de cerrar una conexión inactiva (30 minutos)
TIMEOUT_IN_SECONDS = 30 * 60 

# Mapeo para el Modo de Dispositivo (ID Adicional 0x33)
MODE_MAP = {
    0x00: "Modo Normal (Seguimiento Continuo)",
    0x01: "Modo de Ultra-larga duración (Ahorro de energía)",
    0x04: "Modo de Punto Residente (Ahorro de energía inteligente)",
}

# --- Utilidades y Protocolo Base ---

def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808 (remueve 0x7e y maneja 0x7d).
    Esto asegura que el checksum y el parseo del payload sean correctos.
    """
    # 1. Quitar los delimitadores inicial y final (0x7e) si están presentes
    if data_bytes_with_delimiters.startswith(b'\x7e') and data_bytes_with_delimiters.endswith(b'\x7e'):
        data_to_unescape = data_bytes_with_delimiters[1:-1]
    else:
        # Si no hay delimitadores, asumimos que ya está parcialmente procesado
        data_to_unescape = data_bytes_with_delimiters
    
    # 2. Revertir el proceso de escape (0x7d 0x01 -> 0x7d, 0x7d 0x02 -> 0x7e)
    unescaped_bytes = bytearray()
    i = 0
    while i < len(data_to_unescape):
        if data_to_unescape[i] == 0x7d and i + 1 < len(data_to_unescape):
            next_byte = data_to_unescape[i+1]
            if next_byte == 0x01: 
                unescaped_bytes.append(0x7d)
                i += 2
            elif next_byte == 0x02: 
                unescaped_bytes.append(0x7e)
                i += 2
            else: 
                # Byte de escape 0x7d no seguido de 0x01 o 0x02, lo mantiene
                unescaped_bytes.append(data_to_unescape[i])
                i += 1
        else: 
            unescaped_bytes.append(data_to_unescape[i])
            i += 1
            
    return bytes(unescaped_bytes)

def escape_jt808(data_bytes):
    """Escapa los bytes de un mensaje JT/T 808 para su transmisión (ACK)."""
    escaped = data_bytes.replace(b'\x7d', b'\x7d\x01')
    return b'\x7e' + escaped.replace(b'\x7e', b'\x7d\x02') + b'\x7e'

def create_jt808_packet(message_id, terminal_phone_number_raw, serial_number_raw, body):
    """Construye un paquete JT/T 808 completo (Usado para el ACK 0x8001)."""
    body_length = len(body)
    # Atributos del cuerpo (Longitud en los 10 bits inferiores)
    message_body_attributes = (body_length & 0x03FF).to_bytes(2, 'big') 
    
    # Header: ID (2) + Atributos (2) + Terminal ID (6) + Serial (2)
    header = message_id.to_bytes(2, 'big') + message_body_attributes + terminal_phone_number_raw + serial_number_raw
    
    checksum_payload = header + body
    
    # Cálculo del Checksum (XOR de todos los bytes, incluyendo el header y el body)
    calculated_checksum = 0
    for byte in checksum_payload:
        calculated_checksum ^= byte
    
    raw_frame = checksum_payload + calculated_checksum.to_bytes(1, 'big')
    final_packet = escape_jt808(raw_frame)
    return final_packet, raw_frame.hex()

def parse_status_bits(status_raw):
    """Decodifica los 4 bytes de información de estado de posición básica (similar al documento del proveedor)."""
    status_int = int.from_bytes(status_raw, 'big')
    
    # Mapeo de bits según la convención JT/T 808 estándar (0=Norte/Este)
    acc_status = "ACC off" if (status_int & 0b1) == 0 else "ACC on"
    pos_status_bit = "Positioned" if ((status_int >> 1) & 0b1) == 0 else "Not positioned"
    latitude_type = "North latitude (N)" if ((status_int >> 2) & 0b1) == 0 else "South latitude (S)"
    longitude_type = "East longitude (E)" if ((status_int >> 3) & 0b1) == 0 else "West longitude (W)"
    
    return {
        "ACC status": acc_status,
        "Positioning": pos_status_bit,
        "Latitude direction": latitude_type,
        "Longitude direction": longitude_type,
        "RAW_HEX": hex(status_int)
    }

# --- Decodificadores de Información Adicional (ADDITIONAL INFO) ---

def decode_iccid(value):
    """Decodifica el ICCID (ID 0x00B2)."""
    return f"{value.hex().upper()}"

def decode_extended_status(value):
    """Decodifica el Estado Propietario Extendido (ID 0x0089)."""
    if len(value) == 4:
        status_int = int.from_bytes(value, 'big')
        
        # Bits mapeados según el documento del proveedor
        flags = [
            f"Terminal sleep status: {'1' if (status_int >> 0) & 1 else '0'}",
            f"Card swiping status: {'1' if (status_int >> 1) & 1 else '0'}",
            f"Time period speeding: {'1' if (status_int >> 2) & 1 else '0'}",
            f"Collision alarm: {'1' if (status_int >> 3) & 1 else '0'}",
            f"Evaluator access status: {'1' if (status_int >> 4) & 1 else '0'}",
            f"Top cover closed: {'1' if (status_int >> 5) & 1 else '0'}",
            f"Lifting: {'1' if (status_int >> 6) & 1 else '0'}",
            f"Rapid acceleration alarm: {'1' if (status_int >> 7) & 1 else '0'}",
            f"Rapid deceleration alarm: {'1' if (status_int >> 8) & 1 else '0'}",
            f"Sharp turn alarm: {'1' if (status_int >> 9) & 1 else '0'}",
            f"Vibration trigger status: {'1' if (status_int >> 10) & 1 else '0'}",
        ]
        return f"[RAW: {value.hex()}] | Bits Decodificados:\n      " + "\n      ".join(flags)
    return f"RAW: {value.hex()} (Longitud inesperada)"

def decode_extended_alarm(value):
    """Decodifica el Estado de Alarma Extendido (ID 0x00C5)."""
    if len(value) == 4:
        status_ext_int = int.from_bytes(value, 'big')
        
        charging_status = "Charged" if (status_ext_int & 0b1) else "Not charged"
        
        # Posicionamiento: Bit 1 y 2
        pos_bits = (status_ext_int >> 1) & 0b11
        pos_status = "GPS positioning" if pos_bits == 0b10 else "WIFI positioning" if pos_bits == 0b01 else "Sin Posicionamiento"
        
        return f"RAW: {value.hex()} | Status:\n      Charging status: {charging_status}\n      Positioning: {pos_status}"
    return f"RAW: {value.hex()} (Longitud inesperada)"

def decode_wifi_data(value):
    """Decodifica la información de Wi-Fi (ID 0x00B9)."""
    if not value: return "Datos de Wi-Fi vacíos."
    
    try:
        # El primer byte es el número de elementos
        count = value[0]
        # La cadena MAC/RSSI comienza desde el byte 1
        wifi_data_string = value[1:].decode('ascii', errors='ignore').strip('\x00').strip()
        
        wifi_entries = [e for e in wifi_data_string.split(',') if e]
        
        output = [f"Number of data items: {count}"]
        output.append("Data item data:")
        
        # Agrupa MAC y RSSI
        for i in range(0, len(wifi_entries), 2):
            if i + 1 < len(wifi_entries):
                mac = wifi_entries[i]
                rssi = wifi_entries[i+1]
                output.append(f"      {mac},{rssi}")
        
        return "\n    ".join(output)
    except Exception as e:
        return f"[ERROR] Fallo en decodificación Wi-Fi: {e}"

# Mapeo de IDs adicionales a funciones de decodificación
# Formato: ID (int): (Nombre, Longitud Fija Implícita (si la tiene, 0 si es variable), Función de Decodificación)
ADDITIONAL_INFO_DECODERS = {
    # 1-byte IDs (Longitud de 1 byte después del ID)
    0x01: ("Mileage (km)", 4, lambda v: f"{int.from_bytes(v, 'big') / 10.0:.1f}"),
    0x30: ("Wireless communication network signal strength", 1, lambda v: f"{int.from_bytes(v, 'big')}"),
    0x31: ("Number of GSNN positioning satellites", 1, lambda v: f"{int.from_bytes(v, 'big')}"),
    0x32: ("Exercise duration (s)", 2, lambda v: f"{int.from_bytes(v, 'big')}"),
    0x33: ("Device mode", 1, lambda v: MODE_MAP.get(v[0], "Unknown Mode")),
    
    # 2-byte IDs (Longitud de 1 byte después de los 2 bytes de ID)
    # Nota: 0x000C es una excepción, el proveedor lo usa a veces como Longitud Total
    0x000C: ("Placeholder Desconocido (0x000C)", 0, lambda v: f"RAW: {v.hex()}"), 
    0x00B2: ("ICCID number", 20, decode_iccid),
    0x0089: ("EB extended information ID", 4, decode_extended_status),
    0x00C5: ("Extended alarm status bit", 4, decode_extended_alarm),
    0x002D: ("Unknown information ID (Voltage)", 2, lambda v: f"RAW: {v.hex()}"), 
    0x00A8: ("Battery level (%)", 1, lambda v: f"{v[0]}"),
    0x00D5: ("IMEI", 15, lambda v: v.decode('ascii', errors='ignore').strip('\x00')),
    0x00B9: ("Wifi information point", 0, decode_wifi_data), # Longitud variable
    0xEB: ("Unknown Proprietary ID (0xEB)", 0, lambda v: f"RAW: {v.hex()} (ID que causó el fallo anterior)"),
}

def parse_additional_info(message_body, additional_info_start):
    """
    Extrae y decodifica la información adicional (TLV extendido).
    Busca IDs de 2 bytes (0x00XX) primero, y luego IDs de 1 byte (0xXX).
    """
    current_byte = additional_info_start
    output = []
    
    while current_byte < len(message_body):
        
        additional_id = None
        additional_length = None
        id_raw_hex = None
        id_size = 0
        
        # 1. Intentar parsear ID de 2 bytes (XXYY) + Longitud de 1 byte (Z)
        if current_byte + 3 <= len(message_body):
            id_2_bytes = int.from_bytes(message_body[current_byte:current_byte+2], 'big')
            length_1_byte = message_body[current_byte+2]
            
            if id_2_bytes in ADDITIONAL_INFO_DECODERS:
                additional_id = id_2_bytes
                additional_length = length_1_byte
                id_raw_hex = message_body[current_byte:current_byte+2].hex().upper()
                id_size = 2
                current_byte += 3
        
        # 2. Si el ID de 2 bytes no fue reconocido, intentar ID de 1 byte (X) + Longitud de 1 byte (Y)
        if additional_id is None and current_byte + 2 <= len(message_body):
            id_1_byte = message_body[current_byte]
            
            if id_1_byte in ADDITIONAL_INFO_DECODERS:
                additional_id = id_1_byte
                additional_length = message_body[current_byte+1]
                id_raw_hex = message_body[current_byte:current_byte+1].hex().upper()
                id_size = 1
                current_byte += 2
            
            # Caso especial: Si es 0xEB, que tiene la misma estructura (1-byte ID, 1-byte length)
            elif id_1_byte == 0xEB:
                additional_id = 0xEB
                additional_length = message_body[current_byte+1]
                id_raw_hex = message_body[current_byte:current_byte+1].hex().upper()
                id_size = 1
                current_byte += 2

        # 3. Si no se reconoce, parar el parseo para evitar leer datos basura
        if additional_id is None:
            output.append(f"  [ERROR] ID desconocido o formato inválido en byte {current_byte}. Deteniendo parseo.")
            break

        # Proceso de Decodificación de Valor
        start_value, end_value = current_byte, current_byte + additional_length
        
        if end_value > len(message_body): 
            output.append(f"  [ERROR] Longitud de valor ({additional_length}) para ID 0x{id_raw_hex} excede el cuerpo. Rompiendo.")
            break
        
        additional_value = message_body[start_value:end_value]
        current_byte = end_value # Avanzar al siguiente campo

        # Búsqueda y ejecución de decodificador
        decoder_tuple = ADDITIONAL_INFO_DECODERS.get(additional_id)
        if decoder_tuple:
            desc, _, decoder_func = decoder_tuple
            decoded_value = decoder_func(additional_value)
            
            # Formato de salida similar al del proveedor
            output.append(f"  - [0x{id_raw_hex}] Information ID: {desc}")
            output.append(f"    [{additional_value.hex().upper()}] Value: {decoded_value}")
        else:
            output.append(f"  - [0x{id_raw_hex}] Information ID: Unknown")
            output.append(f"    [{additional_value.hex().upper()}] Value: RAW Data")

    return "\n".join(output)

# --- Función Principal de Parseo del Reporte de Posición ---

def parse_jt808_position_report(payload_for_checksum):
    """
    Decodifica el cuerpo del reporte de posición (0x0200) y la cabecera.
    """
    
    # 1. Cabecera (12 bytes)
    message_id_raw = payload_for_checksum[0:2]
    body_attributes_raw = payload_for_checksum[2:4]
    terminal_phone_number_raw = payload_for_checksum[4:10]
    message_serial_number_raw = payload_for_checksum[10:12]
    
    message_id = int.from_bytes(message_id_raw, 'big')
    body_length = int.from_bytes(body_attributes_raw, 'big') & 0x03FF
    terminal_id = terminal_phone_number_raw.hex()
    message_serial_number = int.from_bytes(message_serial_number_raw, 'big')
    
    message_body = payload_for_checksum[12:12 + body_length]
    
    # 2. Información Básica de Posición (28 bytes)
    # 0-3: Alarm flag (4 bytes)
    alarm_flag_raw = message_body[0:4]
    # 4-7: Status information (4 bytes)
    status_raw = message_body[4:8]
    status_info = parse_status_bits(status_raw)
    # 8-11: Latitude (4 bytes)
    latitude_val = int.from_bytes(message_body[8:12], 'big') / 1_000_000.0
    # 12-15: Longitude (4 bytes)
    longitude_val = int.from_bytes(message_body[12:16], 'big') / 1_000_000.0
    # 16-17: Altitude (2 bytes)
    altitude_val = int.from_bytes(message_body[16:18], 'big')
    # 18-19: Speed (2 bytes)
    speed_val = int.from_bytes(message_body[18:20], 'big') / 10.0
    # 20-21: Direction (2 bytes)
    direction_val = int.from_bytes(message_body[20:22], 'big')
    # 22-27: Terminal Time (6 bytes BCD)
    time_raw = message_body[22:28]
    time_str = datetime.strptime(time_raw.hex(), '%y%m%d%H%M%S').strftime('20%y-%m-%d %H:%M:%S')

    # 3. Información Adicional (a partir del byte 28 del cuerpo)
    additional_info_str = parse_additional_info(message_body, 28)

    # 4. Construir la salida detallada
    
    output = []
    output.append(f"  --- CABECERA DEL MENSAJE ---")
    output.append(f"  [0x{message_id_raw.hex().upper()}] Message ID: {hex(message_id)}")
    output.append(f"  [0x{body_attributes_raw.hex().upper()}] Protocol data length: {body_length} bytes")
    output.append(f"  [0x{terminal_phone_number_raw.hex().upper()}] Terminal mobile phone number: {terminal_id}")
    output.append(f"  [0x{message_serial_number_raw.hex().upper()}] Message serial number: {message_serial_number}")
    output.append(f"\n  --- DATOS BÁSICOS DE POSICIÓN (BODY) ---")
    output.append(f"  [0x{alarm_flag_raw.hex().upper()}] Alarm flag")
    output.append(f"  [0x{status_raw.hex().upper()}] Status information:")
    output.append(f"    - ACC status: {status_info['ACC status']}")
    output.append(f"    - Positioning: {status_info['Positioning']}")
    output.append(f"    - Latitude direction: {status_info['Latitude direction']}")
    output.append(f"    - Longitude direction: {status_info['Longitude direction']}")
    output.append(f"  [0x{message_body[8:12].hex().upper()}] Latitude: {latitude_val:.6f}")
    output.append(f"  [0x{message_body[12:16].hex().upper()}] Longitude: {longitude_val:.6f}")
    output.append(f"  [0x{message_body[16:18].hex().upper()}] Altitude: {altitude_val} m")
    output.append(f"  [0x{message_body[18:20].hex().upper()}] Speed: {speed_val:.1f} km/h")
    output.append(f"  [0x{message_body[20:22].hex().upper()}] Direction: {direction_val}°")
    output.append(f"  [0x{time_raw.hex().upper()}] Terminal Time: {time_str}")
    
    output.append(f"\n  --- INFORMACIÓN ADICIONAL DEL CUERPO (TLV) ---")
    output.append(additional_info_str)
    output.append(f"  --- FIN DE PARSEO DE TRAMA 0x0200 ---")

    return "\n".join(output)

# --- Lógica del Servidor TCP ---

def handle_client(conn, addr):
    """Maneja la conexión con el cliente, enfocado en el ACK del 0x0200."""
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)

    try:
        while True:
            # Recibir datos. Usamos un buffer grande para tramas con datos Wi-Fi.
            data = conn.recv(2048) 
            if not data: break
            
            # 1. Des-escape
            processed_data = unescape_jt808(data)
            
            # 2. Validación Checksum y extracción de Payload
            if not processed_data or len(processed_data) < 13: 
                print(f"  [AVISO] Datos incompletos o vacíos.")
                continue
                
            checksum_received = processed_data[-1]
            payload_for_checksum = processed_data[:-1]
            
            calculated_checksum = 0
            for byte in payload_for_checksum: calculated_checksum ^= byte
            
            if calculated_checksum != checksum_received:
                print(f"  [ERROR] Checksum INCORRECTO. Descartando mensaje.")
                continue

            # 3. Parseo Básico de Cabecera
            message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
            message_serial_number = int.from_bytes(payload_for_checksum[10:12], 'big')
            terminal_phone_number_raw = payload_for_checksum[4:10]
            message_serial_number_raw = payload_for_checksum[10:12]
            
            print(f"\n[DATOS RECIBIDOS de {addr}] (ID: {hex(message_id)}, Serial: {message_serial_number})")

            # 4. Lógica de Decodificación y ACK
            if message_id == 0x0200: # REPORTE DE POSICIÓN
                decoded_report = parse_jt808_position_report(payload_for_checksum)
                print(decoded_report)
                
                # Envío de ACK Universal (0x8001)
                response_message_id = 0x8001
                response_result = 0x00 # Éxito
                # Body: Serial del mensaje original (2 bytes) + ID del mensaje original (2 bytes) + Resultado (1 byte)
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
                
                final_response, _ = create_jt808_packet(response_message_id, terminal_phone_number_raw, message_serial_number_raw, response_body)
                conn.sendall(final_response)
                print(f"    <- [ACK {hex(response_message_id)}] Enviado respuesta a Serial {message_serial_number}.")
            
            elif message_id == 0x0100: # Registro del Terminal (puede necesitar ACK también)
                 print("    -> [Mensaje 0x0100] Recibido registro de terminal. Implementar lógica de respuesta 0x8100.")
            
            else:
                 print(f"    -> [Mensaje {hex(message_id)}] Mensaje recibido no manejado (No 0x0200).")

    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE {addr}] {e}")
    finally:
        conn.close()
        print(f"[CONEXIÓN CERRADA] Cliente {addr}")

def start_server():
    """Inicia el servidor TCP principal para escuchar conexiones entrantes."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"--- SERVIDOR INICIADO ---")
        print(f"Escuchando tramas JT/T 808 en TCP {HOST}:{PORT}")
        print(f"El parseo detallado se mostrará para el ID 0x0200 (Reporte de Posición).\n")
        
        while True:
            conn, addr = server_socket.accept()
            # Manejar cada cliente en un hilo separado
            threading.Thread(target=handle_client, args=(conn, addr)).start()
            
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    # Inicia el servidor.
    start_server()

