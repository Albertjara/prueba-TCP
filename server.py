import socket
import threading
import os
import time
import struct

# --- Configuración del Servidor ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432))
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

# --- Función para Des-escapar Bytes JT/T 808 ---
def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808.
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

# --- Función para parsear sub-campos de la trama extendida 0xEB ---
def parse_extended_eb_fields(additional_value):
    """
    Analiza la sub-trama extendida (ID 0xeb) donde los sub-campos usan ID de 2 bytes.
    """
    sub_data = additional_value
    sub_current_byte = 0
    
    print("    - Contenido del campo 0xEB:")
    
    while sub_current_byte < len(sub_data):
        # El formato interno de 0xEB es: ID de 2 bytes + Longitud de 1 byte + Valor (N bytes)
        if sub_current_byte + 3 > len(sub_data):
            print("      [ERROR DE PARSING] Datos insuficientes para leer el próximo sub-campo (min 3 bytes restantes).")
            break

        sub_id = int.from_bytes(sub_data[sub_current_byte:sub_current_byte+2], 'big')
        sub_length = sub_data[sub_current_byte+2]
        
        start_value = sub_current_byte + 3
        end_value = start_value + sub_length

        if end_value > len(sub_data):
            print(f"      [ERROR DE PARSING] Campo {hex(sub_id)} tiene longitud {sub_length} inválida. Descartando campos restantes.")
            break
            
        sub_value_bytes = sub_data[start_value:end_value]
        
        print(f"      - ID Sub-campo: {hex(sub_id)}, Longitud: {sub_length}, Valor (HEX): {sub_value_bytes.hex()}")

        if sub_id == 0x00B2:
            # 0x00B2 (Número ICCID) - Según el ejemplo, 10 bytes BCD
            try:
                iccid = sub_value_bytes.hex()
                print(f"        - ICCID: {iccid}")
            except Exception:
                 print(f"        - ICCID (Error de decodificación): {sub_value_bytes.hex()}")

        elif sub_id == 0x0089:
            # 0x0089 (Datos extendidos de 4 bytes)
            if sub_length == 4:
                status_bits = int.from_bytes(sub_value_bytes, 'big')
                print(f"        - 0x0089 Estado extendido (bits): {status_bits}")
                # Aquí se podrían decodificar todos los bits según tu lista (Sueño, Deslizamiento tarjeta, Alarma colisión, etc.)

        elif sub_id == 0x00C5:
            # 0x00C5 (Bits de estado de alarma extendidos 4 bytes)
            if sub_length == 4:
                status_bits = int.from_bytes(sub_value_bytes, 'big')
                # El ejemplo muestra 0xFFFFFFF7
                wifi_positioning = (status_bits >> 3) & 0b11 # bits 3 y 4 (según el protocolo de 0x0006)
                charging_status = "No cargando" if (status_bits >> 2) & 1 else "Cargando" # Asunción basada en el ejemplo
                print(f"        - 0x00C5 Estado de alarma extendido (bits): {hex(status_bits)}")
                print(f"          - Carga: {charging_status}")
        
        elif sub_id == 0x002D:
            # 0x002D (Valor de voltaje) - 2 bytes, división por 1000
            if sub_length == 2:
                voltage_mv = int.from_bytes(sub_value_bytes, 'big')
                voltage_v = voltage_mv / 1000.0
                print(f"        - Voltaje: {voltage_v:.3f} V")

        elif sub_id == 0x00A8:
            # 0x00A8 (Porcentaje de batería) - 1 byte, valor directo en %
            if sub_length == 1:
                percentage = sub_value_bytes[0]
                print(f"        - Porcentaje de Batería: {percentage} %")

        elif sub_id == 0x00D5:
            # 0x00D5 (Número IMEI del dispositivo) - 15 bytes, ASCII
            if sub_length == 15:
                try:
                    imei = sub_value_bytes.decode('ascii')
                    print(f"        - IMEI: {imei}")
                except UnicodeDecodeError:
                    print(f"        - IMEI (Error de decodificación): {sub_value_bytes.hex()}")
        
        elif sub_id == 0x00B9:
            # 0x00B9 (Lista de redes Wi-Fi)
            try:
                # El valor es una cadena ASCII con pares MAC, RSSI separados por coma
                wifi_data_string = sub_value_bytes.decode('ascii')
                wifi_entries = wifi_data_string.split(',')
                for i in range(0, len(wifi_entries), 2):
                    if i + 1 < len(wifi_entries):
                        mac = wifi_entries[i]
                        rssi = wifi_entries[i+1]
                        print(f"        - MAC: {mac}, RSSI: {rssi}")
            except (UnicodeDecodeError, IndexError) as e:
                print(f"        - Error de decodificación o formato de la lista de Wi-Fi: {e}")
                print(f"        - Valor (HEX): {sub_value_bytes.hex()}")
        
        # Avanzar al siguiente sub-campo
        sub_current_byte = end_value
        
# --- Función para Manejar Cada Cliente Conectado ---
def handle_client(conn, addr):
    """
    Esta función se ejecuta para cada nuevo cliente que se conecta a tu servidor.
    """
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS)

    try:
        while True:
            data = conn.recv(1024)

            if not data:
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado (no envió más datos o cerró conexión).")
                break
            
            # --- Procesamiento del Mensaje JT/T 808 ---
            processed_data = unescape_jt808(data)
            
            print(f"\n[DATOS RECIBIDOS de {addr}] (Hex Crudo: {data.hex()})")
            print(f"[DATOS PROCESADOS de {addr}] (Hex Des-escapado: {processed_data.hex()})")

            if len(processed_data) < 13: 
                print(f"[ERROR] Datos demasiado cortos para un mensaje JT/T 808 válido. Longitud: {len(processed_data)} bytes.")
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

            if len(payload_for_checksum) < 12:
                print(f"[ERROR] Payload demasiado corto para la cabecera del mensaje. Longitud: {len(payload_for_checksum)} bytes.")
                continue

            message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
            message_body_attributes = int.from_bytes(payload_for_checksum[2:4], 'big')
            terminal_phone_number_raw = payload_for_checksum[4:10]
            message_serial_number_raw = payload_for_checksum[10:12]

            body_length = message_body_attributes & 0x03FF 

            if len(payload_for_checksum) < 12 + body_length:
                print(f"[ERROR] Longitud del cuerpo esperada ({body_length}) es mayor que los bytes disponibles. Disponible: {len(payload_for_checksum) - 12}.")
                continue

            message_body = payload_for_checksum[12:12 + body_length]

            print(f"  --> ID Mensaje: {hex(message_id)}")
            print(f"  --> Atributos del Cuerpo (Hex): {hex(message_body_attributes)}")
            
            terminal_phone_number_str = "".join([f"{b:02x}" for b in terminal_phone_number_raw])
            print(f"  --> Teléfono Terminal (BCD): {terminal_phone_number_str}")
            
            message_serial_number = int.from_bytes(message_serial_number_raw, 'big')
            print(f"  --> Número de Serie: {message_serial_number} (raw: {message_serial_number_raw.hex()})")
            
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # --- Lógica de Respuesta mejorada ---
            response_message_id = None
            response_result = 0x00 # 0x00 para éxito por defecto
            response_body = b''

            if message_id == 0x0100: # Mensaje de Registro del Terminal
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100)")
                # (Lógica de registro omitida por simplicidad)
                response_message_id = 0x8100
                auth_code = b"AUTH_CODE_2025_ABCD"
                response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + auth_code

            elif message_id == 0x0102: # Mensaje de Autenticación del Terminal
                print("  --> Tipo de Mensaje: AUTENTICACIÓN DE TERMINAL (0x0102)")
                # (Lógica de autenticación omitida por simplicidad)
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0200: # Reporte de Información de Posición
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200)")
                if len(message_body) < 28:
                    print("  [ERROR] Cuerpo del mensaje 0x0200 demasiado corto para la información básica.")
                    response_result = 0x01
                else:
                    alarm_flag = int.from_bytes(message_body[0:4], 'big')
                    status = int.from_bytes(message_body[4:8], 'big')
                    latitude_raw = int.from_bytes(message_body[8:12], 'big')
                    longitude_raw = int.from_bytes(message_body[12:16], 'big')
                    elevation = int.from_bytes(message_body[16:18], 'big')
                    speed_raw = int.from_bytes(message_body[18:20], 'big')
                    direction = int.from_bytes(message_body[20:22], 'big')
                    time_raw = message_body[22:28]

                    # Conversiones de valores
                    latitude = latitude_raw / 1_000_000.0
                    longitude = longitude_raw / 1_000_000.0
                    speed = speed_raw / 10.0
                    time_str = f"20{time_raw[0]:02x}-{time_raw[1]:02x}-{time_raw[2]:02x} {time_raw[3]:02x}:{time_raw[4]:02x}:{time_raw[5]:02x} GMT+8"

                    # Decodificación de bits del estado (basado en el ejemplo)
                    acc_status = "Encendido" if status & 1 else "Apagado"
                    position_status = "Posicionado" if (status >> 1) & 1 else "No posicionado"
                    latitude_type = "Sur" if (status >> 2) & 1 else "Norte"
                    longitude_type = "Oeste" if (status >> 3) & 1 else "Este"
                    
                    print("  --- Información de Posición Básica ---")
                    print(f"  - Alarma: {hex(alarm_flag)}")
                    print(f"  - Estado: {hex(status)} (ACC: {acc_status}, Posición: {position_status}, Lat: {latitude_type}, Lon: {longitude_type})")
                    print(f"  - Latitud: {latitude:.6f}")
                    print(f"  - Longitud: {longitude:.6f}")
                    print(f"  - Elevación: {elevation} m")
                    print(f"  - Velocidad: {speed} km/h")
                    print(f"  - Dirección: {direction} grados")
                    print(f"  - Hora: {time_str}")

                    # --- ANÁLISIS DE LA INFORMACIÓN ADICIONAL (ID de 1 byte) ---
                    additional_info_start = 28
                    if len(message_body) > additional_info_start:
                        print("  --- Información Adicional del Cuerpo (ID 1 byte) ---")
                        current_byte = additional_info_start
                        while current_byte < len(message_body):
                            if current_byte + 2 > len(message_body):
                                print("  [ADVERTENCIA] Datos insuficientes para el próximo campo adicional (ID 1 byte).")
                                break

                            additional_id = message_body[current_byte]
                            additional_length = message_body[current_byte+1]
                            
                            start_value = current_byte + 2
                            end_value = start_value + additional_length
                            
                            if end_value > len(message_body):
                                print(f"  [ADVERTENCIA] Datos insuficientes para el campo {hex(additional_id)}. Esperado: {additional_length}, Disponible: {len(message_body) - start_value}. Deteniendo.")
                                break
                            
                            additional_value = message_body[start_value:end_value]
                            
                            print(f"  - ID Adicional: {hex(additional_id)}, Longitud: {additional_length}")
                            
                            # Campos JT/T 808 Estándar y Personalizados (ID de 1 byte)
                            if additional_id == 0x01: # Kilometraje
                                mileage = int.from_bytes(additional_value, 'big')
                                print(f"    - Kilometraje (km): {mileage / 10.0}")
                            elif additional_id == 0x30: # Fuerza de señal
                                signal_strength = int.from_bytes(additional_value, 'big')
                                print(f"    - Fuerza de señal inalámbrica: {signal_strength}")
                            elif additional_id == 0x31: # Número de satélites
                                num_satellites = int.from_bytes(additional_value, 'big')
                                print(f"    - Satélites GSNN de posicionamiento: {num_satellites}")
                            elif additional_id == 0x32: # Duración del ejercicio
                                exercise_duration = int.from_bytes(additional_value, 'big')
                                print(f"    - Duración del ejercicio (segundos): {exercise_duration}")
                            elif additional_id == 0x33: # Modo de dispositivo
                                device_mode = int.from_bytes(additional_value, 'big')
                                mode_desc = "Ultra-larga duración" if device_mode == 0x01 else "Desconocido"
                                print(f"    - Modo de dispositivo: {device_mode} ({mode_desc})")
                            elif additional_id == 0xeb:
                                # Campo 0xEB - Requiere un parseo anidado de sub-campos (ID de 2 bytes)
                                print("    - INICIO DE SUB-TRAMA EXTENDIDA (0xEB) - ID 2 bytes")
                                parse_extended_eb_fields(additional_value)
                                print("    - FIN DE SUB-TRAMA EXTENDIDA (0xEB)")
                            else:
                                print(f"    - Valor (HEX): {additional_value.hex()} (ID no mapeado)")
                            
                            current_byte = end_value # Avanzar al siguiente campo
                
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}")
                print(f"  --> Cuerpo del mensaje (hex): {message_body.hex()}")
                print(f"  No se requiere respuesta automática para el mensaje {hex(message_id)}.")
            
            if response_message_id:
                # Lógica de construcción de respuesta JT/T 808
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
                
                final_response = b'\x7e' + \
                                 checksum_response_payload + \
                                 calculated_response_checksum.to_bytes(1, 'big') + \
                                 b'\x7e'

                # La respuesta debe ser escapada si se usa \x7e o \x7d
                # (Esta parte se omite aquí ya que las respuestas JT/T 808 suelen ser simples)
                conn.sendall(final_response)
                print(f"  [RESPUESTA ENVIADA a {addr}] Mensaje {hex(response_message_id)} con serial {message_serial_number} y resultado {response_result}.")
                print(f"  Respuesta completa (Hex): {final_response.hex()}")

    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo por {TIMEOUT_IN_SECONDS / 60} minutos. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR INESPERADO EN CLIENTE] Problema con cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")
        print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1} cliente(s) conectado(s).")

# --- Función para Iniciar el Servidor Principal ---
def start_server():
    """
    Esta función inicia el servidor y espera nuevas conexiones.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")
        print(f"Esperando conexiones (timeout de inactividad por cliente: {TIMEOUT_IN_SECONDS / 60} minutos)...")

        while True:
            conn, addr = server_socket.accept()
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start()
            print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1} cliente(s) conectado(s).")
            
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")
    finally:
        server_socket.close()
        print("Servidor TCP detenido.")

# --- Punto de Entrada del Programa ---
if __name__ == "__main__":
    start_server()

