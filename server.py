import socket
import threading
import os
import time
import struct
import random 

# --- Configuración del Servidor ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432))
# Establecer un tiempo de espera de 30 minutos para liberar conexiones inactivas
TIMEOUT_IN_SECONDS = 30 * 60 

# --- Mapeo de Valores a Descripciones ---

# Mapeo para el Modo de Dispositivo (ID Adicional 0x33)
MODE_MAP = {
    0x00: "Modo Normal (Seguimiento Continuo)",
    0x01: "Modo de Ultra-larga duración (Ahorro de energía)",
}

# --- Función para Des-escapar Bytes JT/T 808 ---
def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808.
    Elimina el byte delimitador 0x7e al inicio y final, y reemplaza:
    - 0x7d 0x01 -> 0x7d
    - 0x7d 0x02 -> 0x7e
    """
    # Eliminar los delimitadores 0x7e si están presentes
    if data_bytes_with_delimiters.startswith(b'\x7e') and \
       data_bytes_with_delimiters.endswith(b'\x7e'):
        data_to_unescape = data_bytes_with_delimiters[1:-1]
    else:
        data_to_unescape = data_bytes_with_delimiters

    unescaped_bytes = bytearray()
    i = 0
    while i < len(data_to_unescape):
        if data_to_unescape[i] == 0x7d:
            # Si encontramos 0x7d, debemos revisar el siguiente byte para des-escapar
            if i + 1 < len(data_to_unescape):
                next_byte = data_to_unescape[i+1]
                if next_byte == 0x01:
                    unescaped_bytes.append(0x7d) # Des-escapar 0x7d 0x01 -> 0x7d
                    i += 2
                elif next_byte == 0x02:
                    unescaped_bytes.append(0x7e) # Des-escapar 0x7d 0x02 -> 0x7e
                    i += 2
                else:
                    # En caso de 0x7d no seguido de 0x01 o 0x02, se mantiene 0x7d
                    unescaped_bytes.append(data_to_unescape[i])
                    i += 1
            else:
                unescaped_bytes.append(data_to_unescape[i])
                i += 1
        else:
            unescaped_bytes.append(data_to_unescape[i])
            i += 1
    return bytes(unescaped_bytes)

# --- Función para Escapar Bytes JT/T 808 para Respuestas ---
def escape_jt808(data_bytes):
    """
    Escapa los bytes de un mensaje JT/T 808 para su transmisión:
    - 0x7d -> 0x7d 0x01
    - 0x7e -> 0x7d 0x02
    """
    # Importante: reemplazar 0x7d primero para no escapar el byte de reemplazo 0x7d 0x02
    escaped = data_bytes.replace(b'\x7d', b'\x7d\x01')
    escaped = escaped.replace(b'\x7e', b'\x7d\x02')
    return escaped

# --- Constructor de Paquetes JT/T 808 ---
def create_jt808_packet(message_id, terminal_phone_number_raw, serial_number_raw, body):
    """
    Construye un paquete JT/T 808 completo (Header + Body + Checksum + Escaping + Delimiters).
    """
    body_length = len(body)
    # Atributos: Longitud del cuerpo (10 bits inferiores)
    message_body_attributes = (body_length & 0x03FF).to_bytes(2, 'big')

    # Header: ID + Atributos + Teléfono + Serie
    header = message_id.to_bytes(2, 'big') + \
             message_body_attributes + \
             terminal_phone_number_raw + \
             serial_number_raw
    
    # Payload para Checksum: Header + Body
    checksum_payload = header + body

    # Calcular Checksum (XOR de todos los bytes del Header y Body)
    calculated_checksum = 0
    for byte in checksum_payload:
        calculated_checksum ^= byte
    
    # Trama RAW: Payload + Checksum
    raw_frame = checksum_payload + calculated_checksum.to_bytes(1, 'big')

    # Escapar la Trama RAW
    escaped_frame = escape_jt808(raw_frame)

    # Añadir Delimitadores (0x7e)
    final_packet = b'\x7e' + escaped_frame + b'\x7e'
    
    return final_packet, raw_frame.hex()

# --- Constructor de Comando 0x8103 (Establecer Parámetros) ---
def build_set_parameters_command(phone_number_raw, current_serial_number):
    """
    Construye un comando 0x8103 (Establecer Parámetros).
    Se recomienda enviar un serial diferente al último recibido del terminal.
    """
    COMMAND_ID = 0x8103
    
    # Parámetro 1: ID 0x0027 (Intervalo de reporte de posición), Longitud 4 bytes
    param_id_27 = 0x0027
    param_len_27 = 0x04
    param_value_27 = 60 # 60 segundos (4 bytes)
    
    # Parámetro 2: ID 0x0045 (Umbral de bajo voltaje), Longitud 4 bytes (Float)
    param_id_45 = 0x0045
    param_len_45 = 0x04
    # 3.5V (Umbral de bajo voltaje) convertido a 4 bytes IEEE 754 Big-Endian
    param_value_45 = struct.pack('>f', 3.5) 
    
    # Cuerpo del mensaje 0x8103:
    body_payload = b'\x02' # Conteo de Parámetros (N=2)
    
    # Parámetro 1 (Intervalo)
    body_payload += param_id_27.to_bytes(4, 'big') # ID de Parámetro (4 bytes)
    body_payload += param_len_27.to_bytes(1, 'big') # Longitud de Valor (1 byte)
    body_payload += param_value_27.to_bytes(4, 'big') # Valor (4 bytes)
    
    # Parámetro 2 (Low Voltage)
    body_payload += param_id_45.to_bytes(4, 'big') # ID de Parámetro (4 bytes)
    body_payload += param_len_45.to_bytes(1, 'big') # Longitud de Valor (1 byte)
    body_payload += param_value_45  # Valor (4 bytes, Float BE)
    
    # Usar el siguiente número de serie para el comando
    command_serial_raw = ((current_serial_number + 1) % 65536).to_bytes(2, 'big')
    
    print("\n    -> [COMANDO] Preparando comando de Establecer Parámetros (0x8103):")
    print(f"        - Parámetros: 1. Intervalo de Reporte (ID 0x0027) = {param_value_27} s.")
    print(f"        - Parámetros: 2. Umbral de Bajo Voltaje (ID 0x0045) = 3.5 V.")


    final_packet, raw_frame_hex = create_jt808_packet(
        COMMAND_ID,
        phone_number_raw,
        command_serial_raw,
        body_payload
    )
    
    return final_packet, command_serial_raw, raw_frame_hex, COMMAND_ID

# --- Función para interpretar los bits de estado de posición (4 bytes) ---
def parse_status_bits(status_raw):
    """
    Decodifica los 4 bytes de información de estado de posición (Parte estándar del cuerpo 0x0200).
    """
    status_int = int.from_bytes(status_raw, 'big')
    
    # Bit 0: Estado ACC
    acc_status = "Encendido (ACC ON)" if (status_int & 0b1) == 1 else "Apagado (ACC OFF)"
    
    # Bit 1: Posicionamiento (0x0200 estándar JT/T 808)
    pos_bit_std = (status_int >> 1) & 0b1
    pos_status_std = "Posicionado (GPS/BDS/GLONASS)" if pos_bit_std == 0 else "No Posicionado" # El estándar JT/T 808 indica 0: Posicionado, 1: No Posicionado. Se invierte para la mayoría de dispositivos.
    # Nota: Algunos dispositivos invierten Bit 1 (1: Posicionado, 0: No Posicionado)
    pos_status_std_alt = "Posicionado (Asunción Inversa)" if pos_bit_std == 1 else "No Posicionado (Asunción Inversa)"

    # Bit 29: Tipo Latitud (0: Norte, 1: Sur)
    latitude_type = "Sur (S)" if (status_int >> 29) & 0b1 else "Norte (N)" 
    
    # Bit 30: Tipo Longitud (0: Este, 1: Oeste)
    longitude_type = "Oeste (W)" if (status_int >> 30) & 0b1 else "Este (E)" 

    return {
        "Raw Hex": status_raw.hex(),
        "Estado ACC": acc_status,
        "Estado Posición Estándar (Bit 1)": pos_status_std,
        "Estado Posición (Asunción Inversa)": pos_status_std_alt,
        "Tipo Latitud": latitude_type,
        "Tipo Longitud": longitude_type,
        "Valor RAW Completo": hex(status_int)
    }

# --- Función para parsear sub-campos de la trama extendida 0xEB (Proprietaria) ---
def parse_extended_eb_fields(additional_value):
    """
    Analiza la sub-trama extendida (ID 0xeb) utilizando la estructura propietaria L(2)-ID(2)-Valor(L-2).
    Longitud L (2 bytes) = Longitud de ID (2 bytes) + Longitud de Valor (V bytes)
    """
    sub_data = additional_value
    
    # El protocolo tiene un encabezado fijo propietario de 15 bytes antes de los campos L-ID-Valor.
    initial_offset = 15
    sub_current_byte = initial_offset
    
    print("    - INICIO DE DECODIFICACIÓN DETALLADA DE 0xEB (Información Extendida Propietaria):")
    print(f"      [DEBUG] Saltando {initial_offset} bytes de encabezado propietario: {sub_data[0:initial_offset].hex()}")

    if sub_current_byte >= len(sub_data):
        print("      [AVISO] No hay datos restantes después de saltar el encabezado de 15 bytes.")
        return

    while sub_current_byte < len(sub_data):
        
        # 1. Leer Longitud Total del Bloque (L, 2 bytes, Big-Endian)
        if sub_current_byte + 2 > len(sub_data): 
            print(f"      [AVISO] Datos insuficientes para leer la longitud total del bloque. Posición: {sub_current_byte}. Rompiendo ciclo.")
            break
            
        sub_length_block = int.from_bytes(sub_data[sub_current_byte:sub_current_byte+2], 'big')
        
        # 2. Leer ID del Bloque (T, 2 bytes, Big-Endian)
        id_start = sub_current_byte + 2
        if id_start + 2 > len(sub_data): 
            print(f"      [AVISO] Datos insuficientes para leer el ID del bloque. Posición: {id_start}. Rompiendo ciclo.")
            break
            
        sub_id_raw_full = sub_data[id_start:id_start+2]
        # El ID Lógico para el mapeo es el byte menos significativo (LSB) del campo ID (T).
        sub_id_int_1byte = sub_id_raw_full[1] 
        # Para impresión, usamos el valor completo como 0x00XX
        logical_id_for_print = int.from_bytes(b'\x00' + sub_id_raw_full[1].to_bytes(1, 'big'), 'big')
        
        # 3. Calcular Longitud y Bytes del Valor
        value_start = id_start + 2
        
        # La longitud del valor es la longitud total del bloque (L) - 2 bytes de ID (T)
        value_length = sub_length_block - 2 
        
        if value_length < 0 or sub_length_block < 2:
             print(f"      [ERROR] Longitud de valor calculada inválida ({value_length}) para el campo {hex(logical_id_for_print)}. Rompiendo ciclo.")
             break
        
        value_end = value_start + value_length

        if value_end > len(sub_data):
            print(f"      [ERROR] Longitud de valor inválida ({value_length} bytes) para el campo {hex(logical_id_for_print)}. Fin esperado: {value_end}. Real: {len(sub_data)}. Rompiendo ciclo.")
            break
            
        sub_value_bytes = sub_data[value_start:value_end]
        
        print(f"      > Campo ID (RAW): {sub_id_raw_full.hex()} | ID Lógico: {hex(logical_id_for_print)} | Longitud Valor: {value_length} bytes | HEX: {sub_value_bytes.hex()}")

        # --- Decodificación Específica por ID Lógico (LSB) ---
        
        if sub_id_int_1byte == 0x89: # Estado Propietario Extendido (4 bytes)
            if value_length == 4:
                status_prop_ext_int = int.from_bytes(sub_value_bytes, 'big')
                
                # Bit 0: Estado de suspensión del terminal (0: Activo, 1: Dormido)
                sleep_status = "Dormido" if (status_prop_ext_int & 0b1) == 1 else "Activo"
                # Bit 6: Is it lifted (0: No Levantado/Normal, 1: Levantamiento/Alarma)
                lift_status = "**LEVANTADO**" if (status_prop_ext_int >> 6) & 0b1 else "Normal (No Levantado)"
                
                print(f"        -> **Estado Propietario Extendido (ID 0x0089)** (RAW): {sub_value_bytes.hex()} (Valor: {hex(status_prop_ext_int)})")
                print(f"          > Estado de Suspensión (Bit 0): {sleep_status}")
                print(f"          > Estado de Levantamiento (Bit 6): {lift_status}")
            else:
                 print(f"        -> **Estado Propietario Extendido (ID 0x0089)**: Longitud inesperada de {value_length} bytes.")

        elif sub_id_int_1byte == 0xC5: # Estado de Alarma Extendido (4 bytes)
            if value_length == 4:
                status_ext_int = int.from_bytes(sub_value_bytes, 'big')
                
                # Bits 3 y 4: Estado de Posicionamiento Propietario
                pos_bits = (status_ext_int >> 3) & 0b11
                if pos_bits == 0b10: pos_status = "Posicionamiento GPS"
                elif pos_bits == 0b01: pos_status = "Posicionamiento Wi-Fi"
                elif pos_bits == 0b11: pos_status = "Posicionamiento GPS y Wi-Fi"
                else: pos_status = "Sin Posicionamiento"

                # Bit 6: Alarma de Vibración (1: Normal, 0: Alarma)
                vibration_bit = (status_ext_int >> 6) & 0b1
                vibration_status = "Normal (No Vibración)" if vibration_bit == 1 else "**ALARMA DE VIBRACIÓN**"
                
                print(f"        -> **Estado de Alarma Extendido (ID 0x00C5)** (RAW): {hex(status_ext_int)}")
                print(f"          > Posicionamiento Adicional (Bits 3-4): {pos_status}")
                print(f"          > Estado de Vibración (Bit 6): {vibration_status}")

        elif sub_id_int_1byte == 0x2D: # Voltaje del Dispositivo (2 bytes, mV)
            # L=4, Longitud de Valor=2.
            if value_length == 2:
                # El valor del voltaje (mV) se lee como BE
                voltage_mv = int.from_bytes(sub_value_bytes, 'big') 
                voltage_v = voltage_mv / 1000.0
                print(f"        -> **Voltaje (ID 0x002D)**: **{voltage_v:.3f} V** (RAW: {voltage_mv} mV)")
            else:
                 print(f"        -> **Voltaje (ID 0x002D)**: Longitud inesperada de {value_length} bytes.")

        elif sub_id_int_1byte == 0xA8: # Porcentaje de Batería (1 byte)
            # L=3, Longitud de Valor=1.
            if value_length == 1:
                percentage = sub_value_bytes[0]
                print(f"        -> **Porcentaje de Batería (ID 0x00A8)**: **{percentage} %**")
            else:
                 print(f"        -> **Porcentaje de Batería (ID 0x00A8)**: Longitud inesperada de {value_length} bytes.")

        elif sub_id_int_1byte == 0xD5: # IMEI (15 bytes)
            # L=17, Longitud de Valor=15.
            if value_length >= 15:
                try:
                    # El IMEI se decodifica como ASCII o BCD
                    imei = sub_value_bytes[:15].decode('ascii', errors='ignore').strip('\x00')
                    print(f"        -> **IMEI del Dispositivo (ID 0x00D5)**: {imei}")
                except UnicodeDecodeError:
                    print(f"        -> [ERROR] IMEI (No se pudo decodificar): {sub_value_bytes.hex()}")

        elif sub_id_int_1byte == 0xB9: # Wi-Fi
            if sub_value_bytes:
                try:
                    count = sub_value_bytes[0]
                    wifi_data_bytes = sub_value_bytes[1:]
                    
                    # Los datos Wi-Fi son una cadena de pares MAC,RSSI separados por comas
                    wifi_data_string = wifi_data_bytes.decode('ascii', errors='ignore').strip('\x00').strip()
                    wifi_entries = [e for e in wifi_data_string.split(',') if e]
                    
                    print(f"        -> **Redes Wi-Fi Encontradas (ID 0x00B9)** (Contador: {count}, Pares: {len(wifi_entries)//2}):")
                    for i in range(0, len(wifi_entries), 2):
                        if i + 1 < len(wifi_entries):
                            mac = wifi_entries[i]
                            rssi = wifi_entries[i+1]
                            print(f"          > MAC: {mac}, RSSI (dBm): {rssi}")
                except Exception as e:
                    print(f"        -> [ERROR] Error de decodificación de datos Wi-Fi: {e}")
            else:
                 print("        -> **Redes Wi-Fi Encontradas (ID 0x00B9)**: Datos de Wi-Fi vacíos.")
        
        else:
            print(f"        -> ID {hex(logical_id_for_print)} (No Mapeado): {sub_value_bytes.hex()}")
        
        # Avanzar al inicio del siguiente bloque: 2 bytes L + L bytes (ID + Value)
        sub_current_byte = sub_current_byte + 2 + sub_length_block
        
    print("    - FIN DE DECODIFICACIÓN DETALLADA DE 0xEB.")


# --- Función para Manejar Cada Cliente Conectado ---
def handle_client(conn, addr):
    """
    Maneja la conexión con el cliente, parseando mensajes JT/T 808 y enviando respuestas.
    """
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)
    
    # Almacena el último número de serie del terminal para usar el siguiente en comandos
    last_terminal_serial = 0 
    terminal_phone_number_raw = None

    try:
        while True:
            # Recibir datos del socket (paquete completo o fragmento)
            data = conn.recv(1024)

            if not data:
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado (no data).")
                break
            
            # Des-escapar los bytes de la trama recibida
            processed_data = unescape_jt808(data)
            
            print(f"\n[DATOS RECIBIDOS de {addr}] (Hex Crudo: {data.hex()})")
            print(f"[DATOS PROCESADOS de {addr}] (Hex Des-escapado: {processed_data.hex()})")

            if len(processed_data) < 13: # Mínimo: 2 ID + 2 Atrib + 6 Teléfono + 2 Serie + 1 Checksum
                print(f"[ERROR] Datos demasiado cortos para un mensaje válido.")
                continue

            # 1. Validación del Checksum
            checksum_received = processed_data[-1]
            payload_for_checksum = processed_data[:-1]

            calculated_checksum = 0
            for byte in payload_for_checksum:
                calculated_checksum ^= byte
            
            if calculated_checksum == checksum_received:
                print(f"  [DEBUG] Checksum OK: {hex(checksum_received)}")
            else:
                print(f"  [ERROR] Checksum INCORRECTO. Recibido: {hex(checksum_received)}, Calculado: {hex(calculated_checksum)}. Descartando mensaje.")
                continue

            # 2. Parsear Cabecera del Mensaje
            message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
            message_body_attributes = int.from_bytes(payload_for_checksum[2:4], 'big')
            terminal_phone_number_raw = payload_for_checksum[4:10] # Almacenar para usar en respuestas
            message_serial_number_raw = payload_for_checksum[10:12]

            body_length = message_body_attributes & 0x03FF # Extraer longitud (10 bits inferiores)
            message_body = payload_for_checksum[12:12 + body_length]

            terminal_phone_number_str = terminal_phone_number_raw.hex()
            message_serial_number = int.from_bytes(message_serial_number_raw, 'big')
            last_terminal_serial = message_serial_number  # Actualizar el serial

            print(f"  --> ID Mensaje: {hex(message_id)}")
            print(f"  --> Teléfono Terminal (BCD - 6 bytes): {terminal_phone_number_str}")
            print(f"  --> Número de Serie (Trama): {message_serial_number}")
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # 3. Lógica de Respuesta/Comando
            response_message_id = None
            response_result = 0x00 # 0x00 = Éxito / 0x01 = Fallo
            response_body = b''
            send_command_after_response = False  # Flag para enviar un comando después del ACK

            # Manejo del Registro de Terminal (0x0100)
            if message_id == 0x0100: 
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100) - INICIANDO LOGIN")
                
                try:
                    # Decodificación de campos de texto (se asume GB18030 o similar para 808)
                    manufacturer_id = message_body[4:9].decode('gb18030').strip('\x00').strip()
                    model_terminal = message_body[9:29].decode('gb18030').strip('\x00').strip()
                    terminal_id_raw = message_body[29:36] 
                    terminal_id_str = terminal_id_raw.hex()
                    
                    print(f"    - ID Fabricante: {manufacturer_id}")
                    print(f"    - Modelo de Terminal: {model_terminal}")
                    print(f"    - ID Terminal (BCD - 7 bytes): {terminal_id_str}")

                    # Respuesta de Registro (0x8100)
                    response_message_id = 0x8100 
                    auth_code = b"AUTH_CODE_BSJ_2025"  # Código de autenticación
                    response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + auth_code
                    print(f"    -> [RESPUESTA] Envío de Código de Autenticación: {auth_code.decode('latin-1')}")
                    send_command_after_response = True  # Marcar para enviar comando después

                except Exception as e:
                    print(f"    [ERROR GRAVE] Fallo al decodificar campos de texto del registro: {e}")
                    response_result = 0x01 # Fallo en el registro
                    response_message_id = 0x8100
                    response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + b''
                
            # Manejo de la Autenticación de Terminal (0x0102)
            elif message_id == 0x0102:
                print("  --> Tipo de Mensaje: AUTENTICACIÓN DE TERMINAL (0x0102)")
                # Respuesta general de la plataforma (0x8001) con éxito (0x00)
                response_message_id = 0x8001
                # Cuerpo: Serial de la trama recibida (2 bytes) + ID de la trama recibida (2 bytes) + Resultado (1 byte)
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
                send_command_after_response = True 

            # Manejo del Reporte de Posición (0x0200)
            elif message_id == 0x0200: 
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200) - DECODIFICANDO DATOS")
                
                if len(message_body) < 28:
                    response_result = 0x01
                    print("    [ERROR] Cuerpo de posición demasiado corto para datos básicos.")
                else:
                    # Decodificación de información básica (28 bytes fijos)
                    status_raw = message_body[4:8] # Byte 4-8: Estado
                    status_data = parse_status_bits(status_raw)

                    latitude_raw = int.from_bytes(message_body[8:12], 'big') # Byte 8-12: Latitud (4 bytes, /1,000,000)
                    longitude_raw = int.from_bytes(message_body[12:16], 'big') # Byte 12-16: Longitud (4 bytes, /1,000,000)
                    time_raw = message_body[22:28] # Byte 22-28: Tiempo (6 bytes BCD)
                    
                    latitude = latitude_raw / 1_000_000.0
                    longitude = longitude_raw / 1_000_000.0
                    
                    try:
                        # Decodificación de la hora BCD (YYMMDDhhmmss)
                        time_str = f"20{time_raw[0]:02x}-{time_raw[1]:02x}-{time_raw[2]:02x} {time_raw[3]:02x}:{time_raw[4]:02x}:{time_raw[5]:02x} (UTC+8)"
                    except IndexError:
                          time_str = f"Hora no válida: {time_raw.hex()}"
                    
                    print("  --- Información de Posición Básica ---")
                    print(f"  - Estado (RAW): {status_data['Valor RAW Completo']}")
                    print(f"  - Posicionamiento Estándar (Bit 1): **{status_data['Estado Posición (Asunción Inversa)']}**")
                    print(f"  - Estado del ACC (Bit 0): {status_data['Estado ACC']}")
                    print(f"  - Latitud: {latitude:.6f} ({status_data['Tipo Latitud']})")
                    print(f"  - Longitud: {longitude:.6f} ({status_data['Tipo Longitud']})")
                    print(f"  - Hora del Reporte: {time_str}")

                    # --- ANÁLISIS DE LA INFORMACIÓN ADICIONAL (ID 1 byte) ---
                    # Comienza después de los 28 bytes fijos
                    additional_info_start = 28
                    if len(message_body) > additional_info_start:
                        print("  --- Información Adicional del Cuerpo (Estructura ID(1)-L(1)-Valor) ---")
                        current_byte = additional_info_start
                        while current_byte < len(message_body):
                            # Asegurar que hay al menos 2 bytes para ID y Longitud
                            if current_byte + 2 > len(message_body): break

                            additional_id = message_body[current_byte]
                            additional_length = message_body[current_byte+1]
                            
                            start_value = current_byte + 2
                            end_value = start_value + additional_length
                            
                            # Asegurar que el valor no excede el cuerpo del mensaje
                            if end_value > len(message_body): break
                            
                            additional_value = message_body[start_value:end_value]
                            
                            print(f"  - ID Adicional: {hex(additional_id)} | Longitud: {additional_length} bytes")
                            
                            if additional_id == 0x33: # Modo de Dispositivo
                                device_mode_int = int.from_bytes(additional_value, 'big')
                                mode_desc = MODE_MAP.get(device_mode_int, "Modo Desconocido")
                                print(f"    -> Modo de Trabajo (0x33): **{mode_desc}** (Valor RAW: {device_mode_int})")
                            
                            elif additional_id == 0x30: # Fuerza de señal inalámbrica
                                signal_strength = int.from_bytes(additional_value, 'big')
                                print(f"    -> Fuerza de señal inalámbrica (0x30): {signal_strength}")

                            elif additional_id == 0xeb:
                                # Decodificación de la trama extendida propietaria
                                parse_extended_eb_fields(additional_value)
                            
                            else:
                                print(f"    -> ID {hex(additional_id)} (No Mapeado): {additional_value.hex()}")
                            
                            current_byte = end_value # Avanzar al inicio del siguiente campo ID(1)-L(1)-Valor
                
                # Respuesta general de la plataforma (0x8001) para el reporte de posición
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            # Manejo del Cierre de Sesión (0x0003)
            elif message_id == 0x0003:
                print("  --> Tipo de Mensaje: CIERRE DE SESIÓN (0x0003).")
                response_message_id = None # No se requiere respuesta según el estándar

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}. No se requiere respuesta.")
            
            # 4. Construcción y Envío de la Respuesta
            if response_message_id:
                final_response, raw_frame_hex = create_jt808_packet(
                    response_message_id,
                    terminal_phone_number_raw,
                    message_serial_number_raw,
                    response_body
                )
                
                conn.sendall(final_response)
                print(f"  [RESPUESTA ENVIADA a {addr}] Mensaje {hex(response_message_id)} con serial {message_serial_number} y resultado {response_result}.")
                print(f"    (Trama RAW HEX: {raw_frame_hex})")

                # --- LÓGICA DE COMANDO (Envío de 0x8103 después de Registro/Autenticación) ---
                if send_command_after_response:
                    command_packet, command_serial, command_raw_hex, command_id = build_set_parameters_command(
                        terminal_phone_number_raw,
                        last_terminal_serial
                    )
                    conn.sendall(command_packet)
                    print(f"  [COMANDO ENVIADO a {addr}] Mensaje {hex(command_id)} con serial {int.from_bytes(command_serial, 'big')}.")
                    print(f"    (Trama RAW HEX: {command_raw_hex})")


    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo por {TIMEOUT_IN_SECONDS/60} minutos. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE] Problema con cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")

# --- Punto de Entrada del Programa ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reutilizar la dirección para evitar errores al reiniciar rápidamente
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) # Aceptar hasta 5 conexiones en cola
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            # Usar un hilo para manejar cada cliente de forma concurrente
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
