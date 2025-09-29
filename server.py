import socket
import threading
import os
import time
import struct
import random # Necesario para generar un Número de Serie único para los comandos

# --- Configuración del Servidor ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432))
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

# --- Mapeo de Valores a Descripciones ---

# Mapeo para el Modo de Dispositivo (ID Adicional 0x33)
MODE_MAP = {
    0x00: "Modo Normal (Seguimiento Continuo)",
    0x01: "Modo de Ultra-larga duración (Ahorro de energía)",
}

# --- Función para Des-escapar Bytes JT/T 808 (Original) ---
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

# --- FUNCIÓN NUEVA: Escapar Bytes JT/T 808 para Respuestas ---
def escape_jt808(data_bytes):
    """
    Escapa los bytes de un mensaje JT/T 808 (reemplaza 0x7d -> 0x7d 0x01 y 0x7e -> 0x7d 0x02).
    """
    escaped = data_bytes.replace(b'\x7d', b'\x7d\x01')
    escaped = escaped.replace(b'\x7e', b'\x7d\x02')
    return escaped

# --- FUNCIÓN NUEVA: Constructor de Paquetes JT/T 808 (Reutilizado para todas las respuestas) ---
def create_jt808_packet(message_id, terminal_phone_number_raw, serial_number_raw, body):
    """
    Construye un paquete JT/T 808 completo (Header + Body + Checksum + Escaping + Delimiters).
    """
    body_length = len(body)
    # Atributos: Longitud del cuerpo (10 bits)
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

# --- FUNCIÓN NUEVA: Construir Comando 0x8103 (Establecer Parámetros) ---
def build_set_parameters_command(phone_number_raw, current_serial_number):
    """
    Construye un comando 0x8103 (Establecer Parámetros).
    Este ejemplo establece el intervalo de reporte de posición en 60 segundos (ID 0x0027).
    """
    COMMAND_ID = 0x8103
    
    # Parámetro 1: ID 0x0027 (Intervalo de reporte de posición), Longitud 4 bytes
    param_id_1 = 0x0027
    param_len_1 = 0x04
    param_value_1 = 60 # 60 segundos
    
    # Cuerpo del mensaje 0x8103:
    # 1. Byte de Conteo de Parámetros (N=1)
    body_payload = b'\x01' 
    
    # 2. Parámetro 1
    body_payload += param_id_1.to_bytes(4, 'big') # ID de Parámetro (4 bytes)
    body_payload += param_len_1.to_bytes(1, 'big') # Longitud de Valor (1 byte)
    body_payload += param_value_1.to_bytes(4, 'big') # Valor (4 bytes)
    
    # Serial de la Trama de Respuesta (aumentado para el nuevo comando)
    command_serial_raw = ((current_serial_number + 1) % 65536).to_bytes(2, 'big')
    
    print("\n    -> [COMANDO] Preparando comando de Establecer Parámetros (0x8103):")
    print(f"        - Parámetros: 1. Intervalo de Reporte (ID 0x0027) = {param_value_1} segundos.")

    final_packet, raw_frame_hex = create_jt808_packet(
        COMMAND_ID,
        phone_number_raw,
        command_serial_raw,
        body_payload
    )
    
    return final_packet, command_serial_raw, raw_frame_hex, COMMAND_ID

# --- Función para interpretar los bits de estado de posición (4 bytes) (Original) ---
def parse_status_bits(status_raw):
    """
    Decodifica los 4 bytes de información de estado de posición (Byte 4-8 del cuerpo 0x0200).
    """
    status_int = int.from_bytes(status_raw, 'big')
    
    # Bit 0: Estado ACC
    acc_status = "Encendido (ACC ON)" if (status_int & 0b1) == 1 else "Apagado (ACC OFF)"
    
    # Bit 1, 2: Posicionamiento (0x0200 estándar JT/T 808)
    # Nota: El bit 1 es el bit de 'Posicionamiento'
    pos_bit_std = (status_int >> 1) & 0b1
    pos_status_std = "Posicionado" if pos_bit_std == 1 else "No Posicionado"
    
    # Bit 29 (31-0, contando desde 0): Tipo Latitud (0: Norte, 1: Sur)
    latitude_type = "Sur (S)" if (status_int >> 29) & 0b1 else "Norte (N)" 
    
    # Bit 30: Tipo Longitud (0: Este, 1: Oeste)
    longitude_type = "Oeste (W)" if (status_int >> 30) & 0b1 else "Este (E)" 

    return {
        "Raw Hex": status_raw.hex(),
        "Estado ACC": acc_status,
        "Estado Posición Estándar (Bit 1)": pos_status_std,
        "Tipo Latitud": latitude_type,
        "Tipo Longitud": longitude_type,
        "Valor RAW Completo": hex(status_int)
    }

# --- Función para parsear sub-campos de la trama extendida 0xEB (CORREGIDA V2) ---
def parse_extended_eb_fields(additional_value):
    """
    Analiza la sub-trama extendida (ID 0xeb) utilizando la estructura L-ID-Valor.
    CORRECCIÓN V2: Se usan Little-Endian para L e ID. El ID lógico debe ser remapeado
    si se lee como Little-Endian.
    """
    sub_data = additional_value
    
    # El dispositivo tiene un bloque de metadatos propietarios al inicio que debe ser ignorado
    initial_offset = 15
    sub_current_byte = initial_offset
    
    print("    - INICIO DE DECODIFICACIÓN DETALLADA DE 0xEB (Información Extendida Propietaria):")
    
    # Imprimimos la data que estamos saltando (solo por depuración)
    print(f"      [DEBUG] Saltando {initial_offset} bytes de encabezado propietario: {sub_data[0:initial_offset].hex()}")

    if sub_current_byte >= len(sub_data):
        print("      [AVISO] No hay datos restantes después de saltar el encabezado.")
        return

    while sub_current_byte < len(sub_data):
        
        # 1. Leer Longitud del Bloque (2 bytes, Little Endian)
        if sub_current_byte + 2 > len(sub_data): 
            print(f"      [AVISO] Datos insuficientes para leer la longitud del bloque. Posición: {sub_current_byte}. Rompiendo ciclo.")
            break
            
        # L: Longitud total del bloque (ID + Valor). LEÍDO COMO LITTLE-ENDIAN.
        sub_length_block = int.from_bytes(sub_data[sub_current_byte:sub_current_byte+2], 'little')
        
        # 2. Leer ID del Bloque (2 bytes, Little Endian)
        id_start = sub_current_byte + 2
        if id_start + 2 > len(sub_data): 
            print(f"      [AVISO] Datos insuficientes para leer el ID del bloque. Posición: {id_start}. Rompiendo ciclo.")
            break
            
        # T: ID del campo. LEÍDO COMO LITTLE-ENDIAN.
        sub_id_raw = sub_data[id_start:id_start+2]
        sub_id_int_le = int.from_bytes(sub_id_raw, 'little')
        
        # El ID lógico es el byte invertido del ID en LE (ej: 0x89FF en documento, trama tiene FF89)
        # Invertimos los bytes para obtener el ID lógico Big-Endian
        # Ejemplo: Si sub_id_raw es b'\x89\xff' (Little-Endian), el ID lógico Big-Endian es b'\xff\x89'
        sub_id_int = int.from_bytes(sub_id_raw, 'big')
        
        # 3. Calcular Longitud y Bytes del Valor
        value_start = id_start + 2
        
        # La longitud del valor es la longitud del bloque (L) - 2 bytes de ID (T)
        value_length = sub_length_block - 2 
        
        if value_length < 0:
             print(f"      [ERROR] Longitud de valor calculada negativa ({value_length}) para el campo {hex(sub_id_int)}. Rompiendo ciclo.")
             break
        
        value_end = value_start + value_length

        if value_end > len(sub_data):
            print(f"      [ERROR] Longitud de valor inválida ({value_length} bytes) para el campo {hex(sub_id_int)}. Fin esperado: {value_end}. Real: {len(sub_data)}. Rompiendo ciclo.")
            break
            
        sub_value_bytes = sub_data[value_start:value_end]
        
        print(f"      > Campo ID (LE): {hex(sub_id_int)} | Longitud Valor: {value_length} bytes | HEX: {sub_value_bytes.hex()}")

        # Mapeamos los IDs LÓGICOS (que en el documento son Big-Endian, pero se leen al revés)
        
        if sub_id_int == 0x89FF: # ID Lógico: 0xFF89 (Estado Propietario Extendido)
            if value_length == 4:
                # El valor en sí mismo es Big-Endian (DWORD)
                status_prop_ext_int = int.from_bytes(sub_value_bytes, 'big')
                
                # Bit 0: Terminal sleep status (0: Activo, 1: Dormido)
                sleep_status = "Dormido" if (status_prop_ext_int & 0b1) == 1 else "Activo"
                # Bit 6: Is it lifted (0: Levantado, 1: No Levantado)
                lift_status = "No Levantado" if (status_prop_ext_int >> 6) & 0b1 else "**LEVANTADO**"
                
                print(f"        -> **Estado Propietario Extendido (ID Lógico 0x0089)** (RAW): {sub_value_bytes.hex()} (Valor: {hex(status_prop_ext_int)})")
                print(f"          > Estado de Suspensión (Bit 0): {sleep_status}")
                print(f"          > Estado de Levantamiento (Bit 6): {lift_status}")
            else:
                 print(f"        -> **Estado Propietario Extendido (ID Lógico 0x0089)**: {sub_value_bytes.hex()}")

        elif sub_id_int == 0xC5FF: # ID Lógico: 0xFFC5 (Estado de Alarma Extendido)
            if value_length == 4:
                # El valor es un DWORD (4 bytes), asumimos Big-Endian
                status_ext_int = int.from_bytes(sub_value_bytes, 'big')
                
                # Bits 3 y 4: Estado de Posicionamiento Propietario
                pos_bits = (status_ext_int >> 3) & 0b11
                if pos_bits == 0b10: pos_status = "Posicionamiento GPS"
                elif pos_bits == 0b01: pos_status = "Posicionamiento Wi-Fi"
                elif pos_bits == 0b11: pos_status = "Posicionamiento GPS y Wi-Fi"
                else: pos_status = "Sin Posicionamiento"

                # Bit 6: Alarma de Vibración (0: Alarma, 1: Normal)
                vibration_bit = (status_ext_int >> 6) & 0b1
                vibration_status = "Normal (No Vibración)" if vibration_bit == 1 else "**ALARMA DE VIBRACIÓN**"
                
                print(f"        -> **Estado de Alarma Extendido (ID Lógico 0x00C5)** (RAW): {hex(status_ext_int)}")
                print(f"          > Posicionamiento Adicional (Bits 3-4): {pos_status}")
                print(f"          > Estado de Vibración (Bit 6): {vibration_status}")

        elif sub_id_int == 0x2D10: # ID Lógico: 0x102D
            print(f"        -> **Voltaje del Dispositivo (ID Lógico 0x002D)**: **¡¡ESTE NO ES EL CAMPO DE VOLTAJE!!** El ID real debe ser 0x002D. Aquí se leyó 0x102D. (Valor RAW: {sub_value_bytes.hex()})")
            # El campo de voltaje es 0x002D (4 bytes en el protocolo JT/T 808 estándar), pero aquí es 2 bytes
            if sub_id_int == 0x7C00: # Intentamos decodificar si el ID fuera 0x007C
                 if value_length == 2:
                    voltage_mv = int.from_bytes(sub_value_bytes, 'big') 
                    voltage_v = voltage_mv / 1000.0
                    print(f"        -> **Voltaje (ID 0x002D/0x007C)**: {voltage_v:.3f} V (RAW: {voltage_mv} mV)")

        elif sub_id_int == 0xA864: # ID Lógico: 0x64A8 (Porcentaje de Batería)
            if value_length == 1:
                percentage = sub_value_bytes[0]
                print(f"        -> **Porcentaje de Batería (ID Lógico 0x00A8)**: {percentage} %")

        elif sub_id_int == 0xD538: # ID Lógico: 0x38D5 (IMEI)
            if value_length >= 15:
                # Decodificamos solo los primeros 15 bytes
                try:
                    imei = sub_value_bytes[:15].decode('ascii').strip('\x00')
                    print(f"        -> **IMEI del Dispositivo (ID Lógico 0x00D5)**: {imei}")
                except UnicodeDecodeError:
                    print(f"        -> [ERROR] IMEI (No se pudo decodificar): {sub_value_bytes.hex()}")

        elif sub_id_int == 0xB905: # ID Lógico: 0x05B9 (Wi-Fi)
            try:
                # El primer byte del valor es el conteo de redes (ej: 0x05)
                count = sub_value_bytes[0]
                wifi_data_bytes = sub_value_bytes[1:]
                
                # Limpiamos el byte de terminación si está presente al final de la cadena ASCII
                if wifi_data_bytes.endswith(b'\x00'):
                    wifi_data_bytes = wifi_data_bytes[:-1]
                
                wifi_data_string = wifi_data_bytes.decode('ascii')
                
                # Las entradas están separadas por comas, incluyendo MAC y RSSI
                wifi_entries = wifi_data_string.split(',')
                
                print(f"        -> **Redes Wi-Fi Encontradas (ID Lógico 0x00B9)** (Contador reportado: {count}, Pares analizados: {len(wifi_entries)//2}):")
                for i in range(0, len(wifi_entries), 2):
                    if i + 1 < len(wifi_entries):
                        mac = wifi_entries[i]
                        rssi = wifi_entries[i+1]
                        print(f"          > MAC: {mac}, RSSI (dBm): {rssi}")
            except (UnicodeDecodeError, IndexError, ValueError) as e:
                print(f"        -> [ERROR] Error de decodificación de datos Wi-Fi: {e}")
                print(f"          -> RAW WiFi Data: {sub_value_bytes.hex()}")
        
        elif sub_id_int == 0xB200: # ID Lógico: 0x00B2 (ICCID/Información SIM)
            print(f"        -> **ICCID/Información SIM (ID Lógico 0x00B2)**: {sub_value_bytes.hex()}")

        else:
            print(f"        -> ID {hex(sub_id_int)} (No Mapeado o ID Invertido): {sub_value_bytes.hex()}")
        
        sub_current_byte = value_end
        
    print("    - FIN DE DECODIFICACIÓN DETALLADA DE 0xEB.")


# --- Función para Manejar Cada Cliente Conectado (Original, Modificada para usar create_jt808_packet) ---
def handle_client(conn, addr):
    """
    Maneja la conexión con el cliente, parseando mensajes y enviando respuestas.
    """
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)
    
    # Almacenamos el último número de serie usado por el terminal para generar comandos
    last_terminal_serial = 0 

    try:
        while True:
            # Intentamos leer 1024 bytes
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

            # Calculamos el Checksum XOR
            calculated_checksum = 0
            for byte in payload_for_checksum:
                calculated_checksum ^= byte
            
            if calculated_checksum == checksum_received:
                print(f"  [DEBUG] Checksum OK: {hex(checksum_received)}")
            else:
                print(f"  [ERROR] Checksum INCORRECTO. Recibido: {hex(checksum_received)}, Calculado: {hex(calculated_checksum)}. Descartando mensaje.")
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
            last_terminal_serial = message_serial_number # Actualizamos el último serial

            print(f"  --> ID Mensaje: {hex(message_id)}")
            print(f"  --> Teléfono Terminal (BCD - 6 bytes): {terminal_phone_number_str}")
            print(f"  --> Número de Serie (Trama): {message_serial_number}")
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # 3. Lógica de Respuesta
            response_message_id = None
            response_result = 0x00 # 0x00 = Éxito
            response_body = b''
            send_command_after_response = False # NUEVA bandera para enviar comando 0x8103

            if message_id == 0x0100: 
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100) - INICIANDO LOGIN")
                
                try:
                    # FIX: Usamos GB18030 para codificación de texto
                    manufacturer_id = message_body[4:9].decode('gb18030').strip('\x00').strip()
                    model_terminal = message_body[9:29].decode('gb18030').strip('\x00').strip()
                    terminal_id_raw = message_body[29:36] # ID de Terminal (7 bytes BCD)
                    terminal_id_str = terminal_id_raw.hex()
                    
                    print(f"    - ID Fabricante (5 bytes GBK): {manufacturer_id}")
                    print(f"    - Modelo de Terminal (20 bytes GBK): {model_terminal}")
                    print(f"    - ID Terminal (7 bytes BCD): {terminal_id_str}")

                    # 0x8100 (Respuesta de registro)
                    response_message_id = 0x8100 
                    auth_code = b"AUTH_CODE_BSJ_2025" 
                    response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + auth_code
                    print(f"    -> [RESPUESTA] Envío de Código de Autenticación: {auth_code.decode('latin-1')}")
                    send_command_after_response = True # Marcar para enviar comando después de registro/auth

                except Exception as e:
                    print(f"    [ERROR GRAVE] Fallo al decodificar campos de texto del registro: {e}")
                    response_result = 0x01
                    response_message_id = 0x8100
                    response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + b''
                
            elif message_id == 0x0102:
                print("  --> Tipo de Mensaje: AUTENTICACIÓN DE TERMINAL (0x0102)")
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
                send_command_after_response = True # Marcar para enviar comando después de registro/auth

            elif message_id == 0x0200: 
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200) - DECODIFICANDO DATOS")
                
                if len(message_body) < 28:
                    response_result = 0x01
                    print("    [ERROR] Cuerpo de posición demasiado corto.")
                else:
                    # Decodificación de información básica
                    status_raw = message_body[4:8]
                    status_data = parse_status_bits(status_raw)

                    latitude_raw = int.from_bytes(message_body[8:12], 'big')
                    longitude_raw = int.from_bytes(message_body[12:16], 'big')
                    time_raw = message_body[22:28]
                    
                    latitude = latitude_raw / 1_000_000.0
                    longitude = longitude_raw / 1_000_000.0
                    
                    try:
                        time_str = f"20{time_raw[0]:02x}-{time_raw[1]:02x}-{time_raw[2]:02x} {time_raw[3]:02x}:{time_raw[4]:02x}:{time_raw[5]:02x} (UTC+8)"
                    except IndexError:
                          time_str = f"Hora no válida: {time_raw.hex()}"
                    
                    print("  --- Información de Posición Básica ---")
                    print(f"  - Estado (RAW): {status_data['Valor RAW Completo']}")
                    print(f"  - Posicionamiento Estándar (Bit 1): **{status_data['Estado Posición Estándar (Bit 1)']}**")
                    print(f"  - Estado del ACC (Bit 0): {status_data['Estado ACC']}")
                    print(f"  - Latitud: {latitude:.6f} ({status_data['Tipo Latitud']})")
                    print(f"  - Longitud: {longitude:.6f} ({status_data['Tipo Longitud']})")
                    print(f"  - Hora del Reporte: {time_str}")

                    # --- ANÁLISIS DE LA INFORMACIÓN ADICIONAL (ID 1 byte) ---
                    additional_info_start = 28
                    if len(message_body) > additional_info_start:
                        print("  --- Información Adicional del Cuerpo (ID 1 byte, Propietario o Extendido) ---")
                        current_byte = additional_info_start
                        while current_byte < len(message_body):
                            if current_byte + 2 > len(message_body): break

                            additional_id = message_body[current_byte]
                            additional_length = message_body[current_byte+1]
                            
                            start_value = current_byte + 2
                            end_value = start_value + additional_length
                            
                            if end_value > len(message_body): break
                            
                            additional_value = message_body[start_value:end_value]
                            
                            print(f"  - ID Adicional: {hex(additional_id)} | Longitud: {additional_length}")
                            
                            if additional_id == 0x33: # Modo de dispositivo
                                device_mode_int = int.from_bytes(additional_value, 'big')
                                mode_desc = MODE_MAP.get(device_mode_int, "Modo Desconocido")
                                print(f"    -> Modo de Trabajo (0x33): **{mode_desc}** (Valor RAW: {device_mode_int})")
                            
                            elif additional_id == 0x30: # Fuerza de señal
                                signal_strength = int.from_bytes(additional_value, 'big')
                                print(f"    -> Fuerza de señal inalámbrica (0x30): {signal_strength}")

                            elif additional_id == 0x31: # ID 0x31: Información Desconocida
                                print(f"    -> ID 0x31 (Desconocido): {additional_value.hex()}")

                            elif additional_id == 0x32: # ID 0x32: Información Desconocida
                                print(f"    -> ID 0x32 (Desconocido): {additional_value.hex()}")

                            elif additional_id == 0xeb:
                                # Llamamos a la función dedicada para decodificar la trama extendida
                                parse_extended_eb_fields(additional_value)
                            
                            else:
                                print(f"    -> ID {hex(additional_id)} (No Mapeado): {additional_value.hex()}")
                            
                            current_byte = end_value 
                
                # Reconocimiento general para el reporte de posición (0x8001)
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0003:
                print("  --> Tipo de Mensaje: CIERRE DE SESIÓN (0x0003).")
                response_message_id = None

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}. No se requiere respuesta.")
            
            # 4. Construcción y Envío de la Respuesta (Usa la nueva función create_jt808_packet)
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

                # --- LÓGICA DE COMANDO (NUEVA INTEGRACIÓN) ---
                if send_command_after_response:
                    # Enviar un comando de ejemplo 0x8103 (Establecer Parámetros: Reporte cada 60s)
                    command_packet, command_serial, command_raw_hex, command_id = build_set_parameters_command(
                        terminal_phone_number_raw,
                        last_terminal_serial
                    )
                    conn.sendall(command_packet)
                    print(f"  [COMANDO ENVIADO a {addr}] Mensaje {hex(command_id)} con serial {int.from_bytes(command_serial, 'big')}.")
                    print(f"    (Trama RAW HEX: {command_raw_hex})")


    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE] Problema con cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")

# --- Función para Iniciar el Servidor Principal (Original) ---
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

# --- Punto de Entrada del Programa (Original) ---
if __name__ == "__main__":
    start_server()
