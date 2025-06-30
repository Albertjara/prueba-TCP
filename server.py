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
# usará el puerto 12345 por defecto. ESTE SERÁ TU "PUERTO FIJO" INTERNO.
PORT = int(os.environ.get('PORT', 12345))

# TIMEOUT_IN_SECONDS: Tiempo máximo que una conexión estará inactiva (sin recibir datos)
# antes de que el servidor la cierre. 30 minutos = 30 * 60 segundos.
# Si tu equipo envía datos cada cierto tiempo (ej. cada 5 minutos),
# asegúrate de que este timeout sea mayor que ese intervalo.
TIMEOUT_IN_SECONDS = 30 * 60 # 30 minutos

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
            data = conn.recv(1024)
            if not data:
                # Si no se reciben datos (y no hay un timeout), significa que el cliente se desconectó.
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado (no envió más datos o cerró conexión).")
                break # Sale del bucle y cierra la conexión
            
            # --- Aquí es donde ANALIZARÁS Y PROCESARÁS la data ---
            # Los datos que recibes (data) son bytes. Para poder leerlos como texto, necesitas decodificarlos.
            # 'utf-8' es una codificación de texto muy común. Si tu equipo envía datos con otra, cámbiala aquí.
            decoded_data = data.decode('utf-8') 
            print(f"[DATOS RECIBIDOS de {addr}] {decoded_data}")
            
            # EJEMPLO DE ANÁLISIS BÁSICO:
            # Puedes hacer lo que necesites con 'decoded_data'.
            # Por ejemplo, si los datos son un número, podrías convertirlos:
            # try:
            #     valor_numerico = float(decoded_data.strip()) # .strip() quita espacios en blanco
            #     print(f"Valor numérico recibido: {valor_numerico}")
            #     # Aquí podrías guardar esto en una base de datos, hacer cálculos, etc.
            # except ValueError:
            #     print(f"No se pudo convertir '{decoded_data}' a número.")

            # O si esperas un formato JSON:
            # import json
            # try:
            #     json_data = json.loads(decoded_data)
            #     print(f"JSON recibido: {json_data}")
            #     # Accede a campos: json_data['sensor_temperatura']
            # except json.JSONDecodeError:
            #     print(f"No se pudo decodificar '{decoded_data}' como JSON.")

            # --- Opcional: Enviar una respuesta al cliente ---
            # Si necesitas enviar una confirmación o algún dato de vuelta al equipo.
            # response = f"Servidor recibió: {decoded_data}".encode('utf-8')
            # conn.sendall(response) # Envía la respuesta de vuelta al cliente

    except socket.timeout:
        print(f"[TIMEOUT] Cliente {addr} inactivo por {TIMEOUT_IN_SECONDS / 60} minutos. Cerrando conexión.")
    except Exception as e:
        print(f"[ERROR] Error inesperado con el cliente {addr}: {e}")
    finally:
        # Esto siempre se ejecuta al final, ya sea por desconexión, error o timeout.
        conn.close() # Cierra la conexión con este cliente
        print(f"[CONEXIÓN CERRADA] Conexión con {addr} cerrada.")

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