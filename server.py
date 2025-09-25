import socket
import threading
import os
import time

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
            
            message_serial_number = int.from_bytes(message_serial_number_raw, 'big') # Corregido a 'big'
            print(f"  --> Número de Serie: {message_serial_number} (raw: {message_serial_number_raw.hex()})")
            
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # --- Lógica de Respuesta mejorada ---
            response_message_id = None
            response_result = 0x00 # 0x00 para éxito por defecto
            response_body = b''

            if message_id == 0x0100: # Mensaje de Registro del Terminal
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100)")
                auth_code = b"AUTH_CODE_2025_ABCD"
                
                response_message_id = 0x8100
                response_body = message_serial_number_raw + response_result.to_bytes(1, 'big')
                
                if response_result == 0x00:
                    response_body += auth_code

            elif message_id == 0x0102: # Mensaje de Autenticación del Terminal
                print("  --> Tipo de Mensaje: AUTENTICACIÓN DE TERMINAL (0x0102)")
                authentication_code_received = message_body.decode('gbk')
                print(f"  --> Código de Autenticación Recibido: {authentication_code_received}")
                
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0104: # Respuesta a consulta de parámetros (enviada por el terminal)
                print("  --> Tipo de Mensaje: RESPUESTA A CONSULTA DE PARÁMETROS (0x0104)")
                response_serial_number_for_query = int.from_bytes(message_body[0:2], 'big') # Corregido a 'big'
                num_parameters = message_body[2]
                print(f"  --> Responde a la consulta con serial {response_serial_number_for_query}")
                print(f"  --> Total de parámetros recibidos: {num_parameters}")
                
                current_byte = 3
                for _ in range(num_parameters):
                    if current_byte + 5 > len(message_body):
                        print("  [ADVERTENCIA] Datos insuficientes para el próximo parámetro. Deteniendo el parsing.")
                        break

                    param_id = int.from_bytes(message_body[current_byte:current_byte+4], 'big')
                    param_length = message_body[current_byte+4]
                    param_value_bytes = message_body[current_byte+5:current_byte+5+param_length]
                    
                    print(f"    - Parámetro ID: {hex(param_id)}, Longitud: {param_length}")
                    
                    if param_id in [0x0010, 0x0013]:
                        param_value = param_value_bytes.decode('gbk')
                        print(f"      Valor (STRING): {param_value}")
                    elif param_id in [0x0001, 0x0018, 0x0027, 0x0029, 0x0055, 0x0056, 0x0080]:
                        param_value = int.from_bytes(param_value_bytes, 'big')
                        print(f"      Valor (DWORD): {param_value}")
                    else:
                        print(f"      Valor (HEX): {param_value_bytes.hex()}")

                    current_byte += 5 + param_length

            elif message_id == 0x0002: # Terminal Heartbeat (Mensaje de latido)
                print("  --> Tipo de Mensaje: HEARTBEAT (0x0002)")
                
                additional_info_start = 0
                if len(message_body) > additional_info_start:
                    print("  --- Información Adicional del Heartbeat ---")
                    current_byte = additional_info_start
                    while current_byte < len(message_body):
                        additional_id = message_body[current_byte]
                        additional_length = message_body[current_byte+1]
                        additional_value = message_body[current_byte+2:current_byte+2+additional_length]
                        print(f"  - ID Adicional: {hex(additional_id)}, Longitud: {additional_length}")
                        print(f"    - Valor (HEX): {additional_value.hex()}")
                        current_byte += 2 + additional_length

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

                    # Decodificación de bits del estado
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

                    # --- ANÁLISIS DE LA INFORMACIÓN ADICIONAL ---
                    additional_info_start = 28
                    if len(message_body) > additional_info_start:
                        print("  --- Información de Posición Adicional ---")
                        current_byte = additional_info_start
                        while current_byte < len(message_body):
                            if current_byte + 2 > len(message_body):
                                print("  [ADVERTENCIA] Datos insuficientes para el próximo campo adicional. Deteniendo el parsing.")
                                break

                            additional_id = message_body[current_byte]
                            additional_length = message_body[current_byte+1]
                            additional_value = message_body[current_byte+2:current_byte+2+additional_length]
                            
                            if len(additional_value) < additional_length:
                                print(f"  [ADVERTENCIA] Datos insuficientes para el campo {hex(additional_id)}. Longitud esperada: {additional_length}, real: {len(additional_value)}. Deteniendo el parsing.")
                                break
                            
                            print(f"  - ID Adicional: {hex(additional_id)}, Longitud: {additional_length}")
                            
                            if additional_id == 0x01:
                                mileage = int.from_bytes(additional_value, 'big')
                                print(f"    - Kilometraje (km): {mileage / 10.0}")
                            elif additional_id == 0x32:
                                battery_voltage = int.from_bytes(additional_value, 'big')
                                print(f"    - Voltaje de Batería (V): {battery_voltage / 100.0}")
                            elif additional_id == 0xeb:
                                print("    - Redes Wi-Fi Detectadas:")
                                try:
                                    wifi_data_string = additional_value.decode('ascii')
                                    # El protocolo BSJ usa un formato de lista simple.
                                    wifi_entries = wifi_data_string.split(',')
                                    for i in range(0, len(wifi_entries), 2):
                                        if i + 1 < len(wifi_entries):
                                            mac = wifi_entries[i]
                                            rssi = wifi_entries[i+1]
                                            print(f"      - MAC: {mac}, RSSI: {rssi}")
                                except UnicodeDecodeError:
                                    print(f"    - Valor (HEX): {additional_value.hex()} (Error de decodificación)")
                            else:
                                print(f"    - Valor (HEX): {additional_value.hex()}")
                            
                            current_byte += 2 + additional_length
                
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}")
                print(f"  --> Cuerpo del mensaje (hex): {message_body.hex()}")
                print(f"  No se requiere respuesta automática para el mensaje {hex(message_id)}.")
            
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
                
                final_response = b'\x7e' + \
                                 checksum_response_payload + \
                                 calculated_response_checksum.to_bytes(1, 'big') + \
                                 b'\x7e'

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
