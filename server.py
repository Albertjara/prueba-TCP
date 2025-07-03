import socket
import threading
import os
import time

# --- Configuración del Servidor ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5432)) # Aseguramos que el puerto por defecto sea 5432
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
            data = conn.recv(1024) # 'data' ya es de tipo 'bytes'

            if not data:
                # Si no se reciben datos (y no hay un timeout), significa que el cliente se desconectó.
                print(f"[DESCONEXIÓN] Cliente {addr} desconectado (no envió más datos o cerró conexión).")
                break # Sale del bucle y cierra la conexión
            
            # --- ¡AQUÍ ES DONDE PROCESAS TUS DATOS BINARIOS! ---
            # Imprime los bytes recibidos en formato hexadecimal para depuración.
            print(f"[DATOS RECIBIDOS de {addr}] (Binario) {data.hex()}")
            
            # O si sospechas que es texto pero con una codificación extraña (como latin-1)
            # que es más permisiva con bytes no-UTF-8:
            # try:
            #     print(f"[DATOS RECIBIDOS de {addr}] (Texto tentativo) {data.decode('latin-1').strip()}")
            # except UnicodeDecodeError:
            #     print(f"[DATOS RECIBIDOS de {addr}] (Binario, falla Latin-1) {data.hex()}")


            # --- EJEMPLOS DE PROCESAMIENTO DE DATOS BINARIOS ---
            # Aquí puedes implementar la lógica para analizar la 'data' (que es de tipo 'bytes').
            # Por ejemplo, si esperas un formato específico de tu equipo:

            # Ejemplo 1: Si los datos son 4 bytes para un ID y el resto es un valor
            # if len(data) >= 4:
            #     sensor_id_bytes = data[0:4]
            #     payload_bytes = data[4:]
            #     print(f"  ID de Sensor (hex): {sensor_id_bytes.hex()}")
            #     print(f"  Payload (hex): {payload_bytes.hex()}")

            # Ejemplo 2: Si los datos son un valor entero de 2 bytes (big-endian)
            # if len(data) >= 2:
            #     valor_entero = int.from_bytes(data[0:2], byteorder='big')
            #     print(f"  Valor Entero: {valor_entero}")
            
            # Ejemplo 3: Si quieres enviar una respuesta de vuelta al cliente
            # response_message = b"Datos recibidos correctamente!\n"
            # conn.sendall(response_message)

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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Permite reutilizar la dirección/puerto

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) # 5 es el número máximo de conexiones pendientes en cola
        print(f"Servidor TCP escuchando en {HOST}:{PORT}")
        print(f"Esperando conexiones (timeout de inactividad por cliente: {TIMEOUT_IN_SECONDS / 60} minutos)...")

        while True:
            conn, addr = server_socket.accept() # Espera y acepta una nueva conexión
            
            # Crea un hilo nuevo para manejar cada cliente, permitiendo múltiples conexiones concurrentes.
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start() # Inicia el hilo del cliente
            
            # Muestra cuántas conexiones activas hay.
            print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1} cliente(s) conectado(s).")
            
    except Exception as e:
        print(f"[ERROR CRÍTICO DEL SERVIDOR] El servidor principal falló: {e}")
    finally:
        server_socket.close() # Asegúrate de cerrar el socket del servidor
        print("Servidor TCP detenido.")

# --- Punto de Entrada del Programa ---
if __name__ == "__main__":
    start_server()
