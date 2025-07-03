import socket
import threading
import os
import time

# --- Configuración del Servidor ---
# HOST: '0.0.0.0' significa que el servidor escuchará en TODAS las direcciones IP
# disponibles en el servidor donde se ejecute. Esto es crucial para Railway.
HOST = '0.0.0.0'

# PORT: Es el puerto en el que tu servidor escuchará.
# Railway te asignará un puerto dinámicamente a través de la variable de entorno 'PORT'.
# Por eso usamos os.environ.get('PORT'). Si no está definida (por ejemplo, cuando pruebas localmente),
# usará el puerto 5432 por defecto, que es el puerto interno configurado en el TCP Proxy de Railway.
PORT = int(os.environ.get('PORT', 5432))

# TIMEOUT_IN_SECONDS: Tiempo máximo que una conexión estará inactiva (sin recibir datos)
# antes de que el servidor la cierre. 30 minutos = 30 * 60 segundos.
# Si tu equipo envía datos cada cierto tiempo (ej. cada 5 minutos),
# asegúrate de que este timeout sea mayor que ese intervalo.
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

# --- Función para Des-escapar Bytes JT/T 808 ---
# Según la sección 1.4.2 "Conversion rules for transferring messages" del protocolo.
def unescape_jt808(data_bytes_with_delimiters):
    """
    Des-escapa los bytes de un mensaje JT/T 808.
    Elimina los bytes 0x7e inicial y final si están presentes.
    Des-escapa las secuencias 0x7d 0x01 -> 0x7d y 0x7d 0x02 -> 0x7e.
    """
    # Quitar los delimitadores 0x7e de inicio y fin si están presentes
    if data_bytes_with_delimiters.startswith(b'\x7e') and \
       data_bytes_with_delimiters.endswith(b'\x7e'):
        data_to_unescape = data_bytes_with_delimiters[1:-1]
    else:
        # Si no tiene los delimitadores, ya es el "core" o un fragmento, procesar directamente
        data_to_unescape = data_bytes_with_delimiters

    unescaped_bytes = bytearray()
    i = 0
    while i < len(data_to_unescape):
        if data_to_unescape[i] == 0x7d:
            # Si encontramos 0x7d, comprobamos el siguiente byte para des-escape
            if i + 1 < len(data_to_unescape):
                if data_to_unescape[i+1] == 0x01:
                    unescaped_bytes.append(0x7d) # Restaurar 0x7d
                    i += 2
                elif data_to_unescape[i+1] == 0x02:
                    unescaped_bytes.append(0x7e) # Restaurar 0x7e
                    i += 2
                else:
                    # Secuencia inesperada después de 0x7d, añadir 0x7d como está
                    unescaped_bytes.append(0x7d)
                    i += 1
            else:
                # 0x7d al final de los datos sin un byte siguiente, añadir como está
                unescaped_bytes.append(0x7d)
                i += 1
        else:
            unescaped_bytes.append(data_to_unescape[i])
            i += 1
    return bytes(unescaped_bytes)

# --- Función para Manejar Cada Cliente Conectado ---
def handle_client(conn, addr):
    """
    Esta función se ejecuta para cada nuevo cliente que se conecta a tu servidor.
    'conn' es el objeto de conexión (el "cable" por donde van y vienen los datos).
    'addr' es la dirección IP y el puerto del cliente que se conectó.
    """
    print(f"[NUEVA CONEXIÓN] Cliente {addr} conectado.")
    conn.settimeout(TIMEOUT_IN_SECONDS) # Establece el timeout para esta conexión

    try:
        while True:
            # Recibe datos del cliente. 1024 es el tamaño máximo de datos (en bytes)
            # que se leerán de una sola vez. Puedes ajustarlo si esperas paquetes muy grandes.
            data = conn.recv(1024) # 'data' ya es de tipo 'bytes'

            if not data:
                # Si no se reciben datos (y no hay un timeout), significa que el cliente se desconectó.
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado (no envió más datos o cerró conexión).")
                break # Sale del bucle y cierra la conexión
            
            # --- Procesamiento del Mensaje JT/T 808 ---
            
            # 1. Des-escapar los datos recibidos
            # Esto eliminará los 0x7e de los extremos y des-escapará los 0x7d 0x01/02
            processed_data = unescape_jt808(data)
            
            print(f"[DATOS RECIBIDOS de {addr}] (Hex Crudo: {data.hex()})")
            print(f"[DATOS PROCESADOS de {addr}] (Hex Des-escapado: {processed_data.hex()})")

            # Asegurarse de que el mensaje tiene al menos la longitud de la cabecera + checksum (12 + 1 = 13 bytes)
            if len(processed_data) < 13: 
                print(f"[ERROR] Datos demasiado cortos para un mensaje JT/T 808 válido (necesita al menos 13 bytes para header + checksum). Longitud: {len(processed_data)} bytes.")
                continue # Saltar al siguiente ciclo o manejar el error

            # 2. Extraer el Checksum (último byte de los datos procesados)
            checksum_received = processed_data[-1]
            # El resto de los datos (todos menos el checksum) son el "payload" para el cálculo del checksum
            payload_for_checksum = processed_data[:-1]

            # 3. Verificar el Checksum
            calculated_checksum = 0
            for byte in payload_for_checksum:
                calculated_checksum ^= byte
            
            if calculated_checksum == checksum_received:
                print(f"  [DEBUG] Checksum OK: {hex(checksum_received)}")
            else:
                print(f"  [ERROR] Checksum INCORRECTO. Recibido: {hex(checksum_received)}, Calculado: {hex(calculated_checksum)}. Descartando mensaje.")
                continue # O puedes decidir procesar el mensaje incluso con checksum incorrecto (no recomendado)


            # 4. Parsear la Cabecera del Mensaje (Message Header - primeros 12 bytes del payload)
            # Asegurarse de que hay al menos 12 bytes para la cabecera
            if len(payload_for_checksum) < 12:
                print(f"[ERROR] Payload demasiado corto para la cabecera del mensaje. Longitud: {len(payload_for_checksum)} bytes.")
                continue

            message_id = int.from_bytes(payload_for_checksum[0:2], 'big') # WORD, Big-Endian
            message_body_attributes = int.from_bytes(payload_for_checksum[2:4], 'big') # WORD, Big-Endian
            terminal_phone_number_raw = payload_for_checksum[4:10] # BCD[6]
            message_serial_number_raw = payload_for_checksum[10:12] # WORD, Big-Endian

            # Extraer la longitud del cuerpo del mensaje de los atributos (últimos 10 bits)
            body_length = message_body_attributes & 0x03FF 

            # Validar que el cuerpo del mensaje tiene la longitud esperada
            if len(payload_for_checksum) < 12 + body_length:
                print(f"[ERROR] Longitud del cuerpo del mensaje esperada ({body_length}) es mayor que los bytes disponibles. Disponible: {len(payload_for_checksum) - 12}.")
                continue

            # Extraer el cuerpo del mensaje
            message_body = payload_for_checksum[12:12 + body_length]

            # Imprimir la información parseada de la Cabecera
            print(f"  --> ID Mensaje: {hex(message_id)}")
            print(f"  --> Atributos del Cuerpo (Hex): {hex(message_body_attributes)}")
            
            # Decodificar el número de teléfono BCD (ej. 012345678901)
            # Cada byte BCD contiene dos dígitos.
            terminal_phone_number_str = "".join([f"{b:02x}" for b in terminal_phone_number_raw])
            print(f"  --> Teléfono Terminal (BCD): {terminal_phone_number_str}")
            
            # Para el número de serie, usamos little-endian si la secuencia observada lo indica,
            # aunque el protocolo diga big-endian para WORDs, ya que los dispositivos a veces varían.
            # Según los logs que enviaste, el número de serie parece incrementar de 1 en 1
            # cuando se interpreta como Little-Endian (ej. 0300 -> 3, 0400 -> 4).
            message_serial_number = int.from_bytes(message_serial_number_raw, 'little') 
            print(f"  --> Número de Serie: {message_serial_number} (raw: {message_serial_number_raw.hex()})")
            
            print(f"  --> Longitud del Cuerpo Esperada: {body_length} bytes (Real: {len(message_body)} bytes)")

            # 5. Parsear el Cuerpo del Mensaje según el Message ID
            if message_id == 0x0100: # Mensaje de Registro del Terminal (Tabla 6 del protocolo)
                print("  --> Tipo de Mensaje: REGISTRO DE TERMINAL (0x0100)")
                if len(message_body) >= 25: # Longitud mínima para los campos fijos
                    provincial_id = int.from_bytes(message_body[0:2], 'big')
                    city_county_id = int.from_bytes(message_body[2:4], 'big')
                    manufacturer_id = message_body[4:9].decode('ascii', errors='ignore').strip('\x00') # Eliminar nulos de relleno
                    terminal_model = message_body[9:17].decode('ascii', errors='ignore').strip('\x00').strip() # Eliminar nulos y espacios
                    terminal_id = message_body[17:24].decode('ascii', errors='ignore').strip('\x00')
                    license_plate_color = message_body[24]
                    license_plate_raw = message_body[25:] # El resto del cuerpo es la matrícula

                    try:
                        # La matrícula debe ser decodificada usando GBK
                        license_plate = license_plate_raw.decode('gbk', errors='ignore') 
                    except UnicodeDecodeError as e:
                        license_plate = f"ERROR DECODIFICANDO PLACA (GBK): {license_plate_raw.hex()} - {e}"

                    print(f"    - ID Provincial: {provincial_id} (0x{provincial_id:04x})")
                    print(f"    - ID Ciudad/Condado: {city_county_id} (0x{city_county_id:04x})")
                    print(f"    - ID Fabricante: '{manufacturer_id}'")
                    print(f"    - Modelo Terminal: '{terminal_model}'")
                    print(f"    - ID Terminal: '{terminal_id}'")
                    print(f"    - Color Matrícula: {hex(license_plate_color)}")
                    print(f"    - Matrícula: '{license_plate}'")
                else:
                    print(f"  [ERROR] Cuerpo del mensaje de registro demasiado corto. Longitud real: {len(message_body)} bytes.")
            
            elif message_id == 0x0002: # Terminal Heartbeat (Mensaje de latido)
                print("  --> Tipo de Mensaje: HEARTBEAT (0x0002)")
                if len(message_body) == 0:
                    print("    - Cuerpo del mensaje de Heartbeat vacío (Esperado)")
                else:
                    print(f"    - Cuerpo del mensaje de Heartbeat (Hex): {message_body.hex()}")
            
            elif message_id == 0x0200: # Reporte de Información de Posición (Tabla 16 del protocolo)
                print("  --> Tipo de Mensaje: REPORTE DE POSICIÓN (0x0200)")
                if len(message_body) >= 28: # Longitud mínima para los campos básicos de posición
                    alarm_flag = int.from_bytes(message_body[0:4], 'big')
                    status = int.from_bytes(message_body[4:8], 'big')
                    
                    # Latitud y Longitud (DWORD, grados * 10^6)
                    latitude_raw = int.from_bytes(message_body[8:12], 'big')
                    longitude_raw = int.from_bytes(message_body[12:16], 'big')
                    latitude = latitude_raw / 1_000_000.0
                    longitude = longitude_raw / 1_000_000.0

                    elevation = int.from_bytes(message_body[16:18], 'big') # WORD, metros
                    speed = int.from_bytes(message_body[18:20], 'big') / 10.0 # WORD, 1/10 km/h
                    direction = int.from_bytes(message_body[20:22], 'big') # WORD, 0-359 grados

                    # Tiempo (BCD[6], YY-MM-DD-hh-mm-ss GMT+8)
                    time_bcd = message_body[22:28]
                    # Puedes implementar una función para decodificar BCD a fecha/hora si es necesario
                    # Para simplificar, lo imprimimos en hex por ahora
                    
                    print(f"    - Bandera de Alarma: {hex(alarm_flag)}")
                    print(f"    - Estado: {hex(status)}")
                    print(f"    - Latitud: {latitude}°")
                    print(f"    - Longitud: {longitude}°")
                    print(f"    - Elevación: {elevation} m")
                    print(f"    - Velocidad: {speed} km/h")
                    print(f"    - Dirección: {direction}°")
                    print(f"    - Tiempo (BCD): {time_bcd.hex()}")

                    # Puedes añadir lógica para los bits de estado y alarma (Tablas 17 y 18)
                    # Por ejemplo, para el bit de posicionamiento en 'status':
                    # if (status >> 1) & 0x01:
                    #     print("      - Estado: Posicionado")
                    # else:
                    #     print("      - Estado: No Posicionado")

                    # Y para información adicional (si existe, según la longitud total del cuerpo)
                    # additional_info_start_byte = 28
                    # if len(message_body) > additional_info_start_byte:
                    #    # Aquí parsearías los items de información adicional (ID, Longitud, Valor)
                    #    # según la Tabla 19 y 20
                    #    pass

                else:
                    print(f"  [ERROR] Cuerpo del mensaje de posición demasiado corto. Longitud real: {len(message_body)} bytes.")

            else:
                print(f"  --> Tipo de Mensaje: ID DESCONOCIDO {hex(message_id)}")
                print(f"  --> Cuerpo del mensaje (hex): {message_body.hex()}")

            # --- Opcional: Enviar una respuesta al cliente (ACK) ---
            # Es muy común que los dispositivos JT/T 808 esperen una respuesta de la plataforma.
            # Para el mensaje 0x0100 (Registro del Terminal), la plataforma debe responder con 0x8100.
            # Para el mensaje 0x0002 (Heartbeat), la plataforma debe responder con 0x8001 (General Response).

            # Ejemplo de respuesta 0x8001 (Plataforma General Response)
            # Necesitas el número de serie del mensaje recibido para la respuesta.
            # Y el ID del mensaje recibido (message_id)
            # Y un resultado (0: éxito, 1: fallo, etc.)

            # Construir una respuesta general (0x8001) para confirmar la recepción
            # Esto es una respuesta simplificada, necesitarías encapsularla con 0x7e y checksum
            # WORD Response serial number (del mensaje recibido)
            # WORD Response ID (del mensaje recibido)
            # BYTE Result (0: Success)

            # Ejemplo de respuesta general (8001) para el mensaje recibido
            # Solo si el mensaje recibido es uno que espera una respuesta (como 0x0100 o 0x0002)
            if message_id in [0x0100, 0x0002, 0x0200]: # Añade IDs que requieren respuesta
                response_message_id = 0x8001 # O 0x8100 para registro
                response_serial_number = message_serial_number_raw # Usar el mismo serial number
                response_result = 0x00 # 0x00 para éxito

                # Construir el cuerpo de la respuesta (serial_number + message_id + result)
                # Para 0x8001 y 0x0001, el cuerpo es Response Serial Number (WORD) + Response ID (WORD) + Result (BYTE)
                response_body = response_serial_number + message_id.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
                
                # Construir la cabecera de la respuesta (simplificado)
                # Message ID (WORD) + Message Body Attributes (WORD) + Terminal Phone Number (BCD[6]) + Message Serial Number (WORD)
                # Atributos: longitud del cuerpo (response_body), no encriptado, no sub-paquetizado
                response_body_len = len(response_body)
                response_attributes = (response_body_len & 0x03FF).to_bytes(2, 'big') # Solo los 10 bits de longitud
                
                # Usar el mismo número de teléfono del terminal que recibimos
                response_header = response_message_id.to_bytes(2, 'big') + \
                                  response_attributes + \
                                  terminal_phone_number_raw + \
                                  message_serial_number_raw # Usar el mismo serial del mensaje recibido

                # Calcular el checksum para la respuesta
                checksum_response_payload = response_header + response_body
                calculated_response_checksum = 0
                for byte in checksum_response_payload:
                    calculated_response_checksum ^= byte
                
                # Ensamblar el mensaje final de respuesta
                final_response = b'\x7e' + \
                                 checksum_response_payload + \
                                 calculated_response_checksum.to_bytes(1, 'big') + \
                                 b'\x7e'

                # Escapar la respuesta si contiene 0x7e o 0x7d (antes de enviar)
                # Nota: La función unescape_jt808 también sirve para "escapar" si la usas al revés,
                # pero es mejor tener una función de escape explícita.
                # Por simplicidad, aquí no se escapa, lo que podría ser un problema si la respuesta contiene 0x7e/0x7d
                # Para una implementación completa, necesitarías una función `escape_jt808`.
                
                conn.sendall(final_response)
                print(f"  [RESPUESTA ENVIADA a {addr}] Mensaje {hex(response_message_id)} con serial {message_serial_number} y resultado {response_result}.")
            else:
                print(f"  No se requiere respuesta automática para el mensaje {hex(message_id)}.")


    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo por {TIMEOUT_IN_SECONDS / 60} minutos. Cerrando conexión.")
    except Exception as e:
        # Asegúrate de capturar cualquier otro error inesperado durante el manejo del cliente
        print(f"[ERROR INESPERADO EN CLIENTE] Problema con cliente {addr}: {e}")
    finally:
        # Esto siempre se ejecuta al final, ya sea por desconexión, error o timeout.
        conn.close() # Cierra la conexión con este cliente
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")
        # Muestra cuántas conexiones activas hay (restamos 1 porque el hilo principal también cuenta).
        # Aunque active_count() no es 100% preciso para conexiones cerradas en tiempo real, da una idea.
        print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1} cliente(s) conectado(s).")

# --- Función para Iniciar el Servidor Principal ---
def start_server():
    """
    Esta función se encarga de iniciar el servidor, bindearlo al puerto
    y esperar nuevas conexiones.
    """
    # Crea un objeto socket.
    # AF_INET: Significa que usaremos direcciones IPv4 (las típicas, como 192.168.1.1).
    # SOCK_STREAM: Significa que usaremos TCP (protocolo orientado a la conexión, fiable).
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Esta línea es para que puedas reiniciar tu servidor rápidamente.
    # Si no la pones y el servidor se cierra bruscamente, podría decirte
    # "Address already in use" al intentar reiniciarlo.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Asocia el socket a la dirección IP y el puerto.
        # Aquí es donde le dices al sistema operativo: "¡Escucha en esta dirección y este buzón!"
        server_socket.bind((HOST, PORT))
        
        # Pone el servidor en modo de escucha.
        # El '5' significa el número máximo de conexiones pendientes que puede tener en cola
        # antes de empezar a rechazarlas.
        server_socket.listen(5) 
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")
        print(f"Esperando conexiones (timeout de inactividad por cliente: {TIMEOUT_IN_SECONDS / 60} minutos)...")

        while True:
            # server_socket.accept() espera y acepta una nueva conexión de un cliente.
            # Cuando un cliente se conecta, devuelve un nuevo socket 'conn' para esa conexión
            # y la dirección 'addr' del cliente.
            conn, addr = server_socket.accept() 
            
            # Para manejar múltiples clientes al mismo tiempo, creamos un "hilo" (thread) nuevo
            # para cada cliente. Un hilo es como un mini-programa que se ejecuta en paralelo.
            # Así, tu servidor puede hablar con varios equipos a la vez sin bloquearse.
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start() # Inicia el hilo del cliente
            
            # Muestra cuántas conexiones activas hay (restamos 1 porque el hilo principal también cuenta).
            print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1} cliente(s) conectado(s).")
            
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")
    finally:
        # Asegúrate de cerrar el socket del servidor cuando el programa termine.
        server_socket.close()
        print("Servidor TCP detenido.")

# --- Punto de Entrada del Programa ---
# Esto asegura que 'start_server()' se llame solo cuando ejecutas este script directamente.
if __name__ == "__main__":
    start_server()
