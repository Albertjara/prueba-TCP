import socket
import threading
import os
import time

# --- Configuración del Servidor ---
# HOST: '0.0.0.0' significa que el servidor escuchará en TODAS las direcciones IP disponibles.
HOST = '0.0.0.0'
# PORT: Se obtiene dinámicamente de Railway o usa 5432 por defecto para pruebas locales.
PORT = int(os.environ.get('PORT', 5432))
# TIMEOUT_IN_SECONDS: Tiempo máximo que una conexión estará inactiva antes de cerrarse.
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

# --- Función para Des-escapar Bytes JT/T 808 ---
def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808.
    Elimina los bytes 0x7e inicial y final si están presentes.
    Des-escapa las secuencias 0x7d 0x01 -> 0x7d y 0x7d 0x02 -> 0x7e.
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
            
            print(f"[DATOS RECIBIDOS de {addr}] (Hex Crudo: {data.hex()})")
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
            
            # Nota: Según los logs, el número de serie parece ser Little-Endian.
            message_serial_number = int.from_bytes(message_serial_number_raw, 'little') 
            print(f"  --> Número de Serie: {message_serial_number} (raw: {message_serial_number_raw.hex()})")
            
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # --- Lógica de Respuesta mejorada ---
            response_message_id = None
            response_result = 0x00 # 0x00 para éxito por defecto
            response_body = b''

            if message_id == 0x0100: # Mensaje de Registro del Terminal
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100)")
                # Aquí puedes añadir lógica para registrar el terminal en una base de datos.
                # El código de autenticación es solo un ejemplo.
                auth_code = b"AUTH_CODE_2025_ABCD"
                
                # Construir el cuerpo de la respuesta 0x8100
                response_message_id = 0x8100
                response_body = message_serial_number_raw + response_result.to_bytes(1, 'big')
                
                # Si el resultado es éxito, se añade el código de autenticación
                if response_result == 0x00:
                    response_body += auth_code

            elif message_id == 0x0002: # Terminal Heartbeat (Mensaje de latido)
                print("  --> Tipo de Mensaje: HEARTBEAT (0x0002)")
                # Construir el cuerpo de la respuesta 0x8001
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            elif message_id == 0x0200: # Reporte de Información de Posición
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200)")
                # Aquí puedes parsear los datos de posición (lat, lon, etc.).
                # Construir el cuerpo de la respuesta 0x8001
                response_message_id = 0x8001
                response_body = message_serial_number_raw + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}")
                print(f"  --> Cuerpo del mensaje (hex): {message_body.hex()}")
                print(f"  No se requiere respuesta automática para el mensaje {hex(message_id)}.")
            
            # Construir y enviar la respuesta si se identificó una
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
