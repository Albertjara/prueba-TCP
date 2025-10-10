import socket
import threading
import os
import time
from datetime import datetime
import random 
import struct
from flask import Flask, request, jsonify
import logging

# --- Configuration and Constants ---
HOST = '0.0.0.0'
# ==============================================================================
# CORRECCIÓN: Cambiamos el puerto por defecto del TCP a 5433 para evitar conflictos
# ==============================================================================
TCP_PORT = int(os.environ.get('TCP_PORT', 5433))

# El puerto para la API web. Usamos la variable 'PORT' que Railway nos da para el servicio web.
API_PORT = int(os.environ.get('PORT', 8080))
TIMEOUT_IN_SECONDS = 30 * 60 

# --- Diccionario de Clientes y Lock ---
connected_clients = {}
clients_lock = threading.Lock()
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- LÓGICA DE PARSING Y UTILIDADES JT/T 808 (DE TU CÓDIGO ORIGINAL) ---

def unescape_jt808(data_bytes_with_delimiters):
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
    escaped = data_bytes.replace(b'\x7d', b'\x7d\x01')
    return b'\x7e' + escaped.replace(b'\x7e', b'\x7d\x02') + b'\x7e'

def calculate_checksum(data):
    calculated_checksum = 0
    for byte in data: calculated_checksum ^= byte
    return calculated_checksum

def create_jt808_packet(message_id, terminal_phone_number_raw, serial_number_raw, body):
    body_length = len(body)
    message_body_attributes = (body_length & 0x03FF).to_bytes(2, 'big') 
    header = message_id.to_bytes(2, 'big') + message_body_attributes + terminal_phone_number_raw + serial_number_raw
    checksum_payload = header + body
    calculated_checksum = calculate_checksum(checksum_payload)
    raw_frame = checksum_payload + calculated_checksum.to_bytes(1, 'big')
    final_packet = escape_jt808(raw_frame)
    return final_packet, raw_frame.hex()

def _parse_status_bits(raw_bytes):
    status_dword = int.from_bytes(raw_bytes, 'big')
    lines = [f"  [{raw_bytes.hex()}] Status Information: ["]
    lines.append(f"    [bit0] ACC Status: {'ACC on' if (status_dword >> 0) & 1 else 'ACC off'}")
    lines.append(f"    [bit1] Positioning: {'Positioned' if (status_dword >> 1) & 1 else 'Not positioned'}")
    lines.append(f"    [bit2] Latitude: {'South Latitude' if (status_dword >> 2) & 1 else 'North Latitude'}")
    lines.append(f"    [bit3] Longitude: {'West Longitude' if (status_dword >> 3) & 1 else 'East Longitude'}")
    lines.append("  ]")
    return lines

def _parse_extended_block(data_bytes):
    lines = []
    idx = 0
    while idx < len(data_bytes):
        try:
            total_len = int.from_bytes(data_bytes[idx:idx+2], 'big')
            idx += 2
            ext_id_bytes = data_bytes[idx:idx+2]
            ext_id = int.from_bytes(ext_id_bytes, 'big')
            idx += 2
            ext_data = data_bytes[idx:idx+(total_len-2)]
            idx += (total_len-2)
            lines.append(f"    [{ext_id_bytes.hex()}] Information ID")
            if ext_id == 0x00b2: lines.append(f"    [{ext_data.hex()}] ICCID Number: {ext_data.hex()}")
            elif ext_id == 0x00a8: lines.append(f"    [{ext_data.hex()}] Battery Level: {int.from_bytes(ext_data, 'big')}")
            elif ext_id == 0x00d5: lines.append(f"    [{ext_data.hex()}] IMEI: {ext_data.decode('ascii', errors='ignore')}")
            elif ext_id == 0x00b9:
                lines.append(f"    [{ext_id_bytes.hex()}] Wi-Fi Hotspot Information ID")
                num_hotspots = ext_data[0]
                wifi_data_str = ext_data[1:].decode('ascii', errors='ignore')
                hotspots = wifi_data_str.split(',')
                lines.append(f"    [{ext_data.hex()}]:[")
                lines.append(f"      Number of items: {num_hotspots},")
                lines.append(f"      Item data:")
                for spot in hotspots: lines.append(f"      {spot}")
                lines.append("    ]")
            else: lines.append(f"    [{ext_data.hex()}] Unknown extended data,")
        except IndexError:
            lines.append("    [ERROR] Malformed extended block (0xEB).")
            break
    return lines

def _parse_additional_info(raw_bytes):
    lines = [f"  [{raw_bytes.hex()}] Location Additional Information List: ["]
    idx = 0
    while idx < len(raw_bytes):
        try:
            info_id = raw_bytes[idx]; idx += 1
            info_len = raw_bytes[idx]; idx += 1
            info_value = raw_bytes[idx:idx + info_len]; idx += info_len
            lines.append(f"    [0x{info_id:02x}] Information ID")
            if info_id == 0x01: lines.append(f"    [{info_value.hex()}] Mileage (km): {int.from_bytes(info_value, 'big')/10.0},")
            elif info_id == 0x30: lines.append(f"    [{info_value.hex()}] Network Signal Strength: {int.from_bytes(info_value, 'big')},")
            elif info_id == 0x31: lines.append(f"    [{info_value.hex()}] Number of GSNN positioning satellites: {int.from_bytes(info_value, 'big')},")
            elif info_id == 0x33:
                modes = { 1: "Ultra-long duration mode", 4: "Intelligent power saving mode at resident point" }
                mode_id = int.from_bytes(info_value, 'big')
                mode_desc = modes.get(mode_id, f"Unknown Mode ({mode_id})")
                lines.append(f"    [{info_value.hex()}] Device Mode: {mode_desc},")
            elif info_id == 0xeb: lines.extend(_parse_extended_block(info_value))
            else: lines.append(f"    [{info_value.hex()}] Unknown data,")
        except IndexError:
            lines.append("    [ERROR] Malformed additional information. Stopping parse.")
            break
    lines.append("]")
    return lines

def parse_jt808_position_report(payload_for_checksum):
    message_body = payload_for_checksum[12:]
    body_length = len(message_body)
    if body_length < 28: return "  [ERROR] Message body 0x0200 is too short."
    output = []
    try:
        idx = 0
        output.append(f"  --- BASIC POSITION DATA (BODY) ---")
        raw_bytes = message_body[idx:idx+4]; idx += 4; output.append(f"  [{raw_bytes.hex()}] Alarm Indicator: []")
        raw_bytes = message_body[idx:idx+4]; idx += 4; output.extend(_parse_status_bits(raw_bytes))
        raw_bytes = message_body[idx:idx+4]; idx += 4; output.append(f"  [{raw_bytes.hex()}] Latitude: {int.from_bytes(raw_bytes, 'big') / 1000000.0}")
        raw_bytes = message_body[idx:idx+4]; idx += 4; output.append(f"  [{raw_bytes.hex()}] Longitude: {int.from_bytes(raw_bytes, 'big') / 1000000.0}")
        raw_bytes = message_body[idx:idx+2]; idx += 2; output.append(f"  [{raw_bytes.hex()}] Altitude: {int.from_bytes(raw_bytes, 'big') / 10.0}")
        raw_bytes = message_body[idx:idx+2]; idx += 2; output.append(f"  [{raw_bytes.hex()}] Speed: {int.from_bytes(raw_bytes, 'big') / 10.0}")
        raw_bytes = message_body[idx:idx+2]; idx += 2; output.append(f"  [{raw_bytes.hex()}] Direction: {int.from_bytes(raw_bytes, 'big')}")
        raw_bytes = message_body[idx:idx+6]; idx += 6
        time_val = datetime.strptime(raw_bytes.hex(), '%y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
        output.append(f"  [{raw_bytes.hex()}] Terminal Time: {time_val}")
        if body_length > idx:
            additional_bytes = message_body[idx:]
            output.append(f"\n  --- ADDITIONAL BODY INFORMATION (TLV) ---")
            output.extend(_parse_additional_info(additional_bytes))
        else:
            output.append(f"\n  --- NO ADDITIONAL INFORMATION ---")
    except (struct.error, ValueError, IndexError) as e:
        return f"  [ERROR] Failed to decode basic position fields: {e}"
    output.append(f"  --- END OF 0x0200 FRAME PARSING ---")
    return "\n".join(output)

# --- Lógica del Servidor TCP ---

def send_ack_8001(conn, terminal_phone_number_raw, message_serial_number_raw, message_id_original):
    response_message_id = 0x8001
    response_result = 0x00
    response_body = message_serial_number_raw + message_id_original.to_bytes(2, 'big') + response_result.to_bytes(1, 'big')
    final_response, _ = create_jt808_packet(response_message_id, terminal_phone_number_raw, message_serial_number_raw, response_body)
    conn.sendall(final_response)
    print(f"    <- [ACK {hex(response_message_id)}] Sent response to Serial {int.from_bytes(message_serial_number_raw, 'big')} (Target: {hex(message_id_original)}).")

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] Client {addr} connected.")
    conn.settimeout(TIMEOUT_IN_SECONDS)
    terminal_id = None 
    try:
        while True:
            data = conn.recv(2048) 
            if not data: break
            print(f"  -> [TRAMA CRUDA de {addr}] {data.hex()} (ASCII: {str(data, 'latin-1', errors='ignore')})")
            try:
                processed_data = unescape_jt808(data)
                if not processed_data or len(processed_data) < 13: continue
                
                checksum_received = processed_data[-1]
                payload_for_checksum = processed_data[:-1]
                calculated_checksum = calculate_checksum(payload_for_checksum)
                if calculated_checksum != checksum_received:
                    print(f"  [ERROR] Checksum INCORRECTO. Descartando mensaje.")
                    continue

                message_id = int.from_bytes(payload_for_checksum[0:2], 'big')
                message_serial_number = int.from_bytes(payload_for_checksum[10:12], 'big')
                terminal_phone_number_raw = payload_for_checksum[4:10]
                message_serial_number_raw = payload_for_checksum[10:12]
                
                current_terminal_id = terminal_phone_number_raw.hex()
                if terminal_id != current_terminal_id:
                    terminal_id = current_terminal_id
                    with clients_lock:
                        connected_clients[terminal_id] = conn
                    print(f"    [INFO] Dispositivo '{terminal_id}' registrado.")
                
                print(f"\n[DATA RECEIVED from {addr}] (ID: {hex(message_id)}, Serial: {message_serial_number})")
                
                if message_id == 0x0100:
                    auth_code = f"AUTH-{random.randint(1000, 9999)}" 
                    auth_code_bytes = auth_code.encode('gbk')
                    response_message_id = 0x8100
                    response_result = 0x00
                    response_body = message_serial_number_raw + response_result.to_bytes(1, 'big') + auth_code_bytes
                    final_response, _ = create_jt808_packet(response_message_id, terminal_phone_number_raw, message_serial_number_raw, response_body)
                    conn.sendall(final_response)
                    print(f"    <- [ACK {hex(response_message_id)}] Sent successful registration response to Serial {message_serial_number}.")
                    print(f"       Assigned Authentication Code: {auth_code}")

                elif message_id == 0x0200:
                    decoded_report = parse_jt808_position_report(payload_for_checksum)
                    print(decoded_report)
                    send_ack_8001(conn, terminal_phone_number_raw, message_serial_number_raw, message_id)
                
                elif message_id == 0x0002:
                    print("    -> [Message 0x0002] Heartbeat recibido.")
                    send_ack_8001(conn, terminal_phone_number_raw, message_serial_number_raw, message_id)

                elif message_id == 0x0003:
                    print("    -> [Message 0x0003] Logout Request recibido.")
                    send_ack_8001(conn, terminal_phone_number_raw, message_serial_number_raw, message_id)
                    time.sleep(0.5)
                    break 

                else:
                     print(f"    -> [Message {hex(message_id)}] Mensaje no manejado recibido.")
                     send_ack_8001(conn, terminal_phone_number_raw, message_serial_number_raw, message_id)

            except Exception:
                pass # Ignorar tramas que no son JT/T 808 (probablemente respuestas a comandos)
    finally:
        if terminal_id:
            with clients_lock:
                if terminal_id in connected_clients:
                    del connected_clients[terminal_id]
        conn.close()
        print(f"[CONNECTION CLOSED] Client {addr}")

def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, TCP_PORT))
    server_socket.listen(5)
    print(f"--- SERVIDOR TCP INICIADO en {HOST}:{TCP_PORT} ---")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# --- Lógica de la API Web Flask ---
app = Flask(__name__)

@app.route('/send_command', methods=['GET'])
def send_command():
    device_id = request.args.get('device_id')
    command_str = request.args.get('command')
    if not device_id or not command_str:
        return jsonify({"status": "error", "message": "Faltan parámetros."}), 400
    with clients_lock:
        client_conn = connected_clients.get(device_id)
        if client_conn:
            try:
                client_conn.sendall(command_str.encode('latin-1'))
                print(f"\n[API] Comando '{command_str}' enviado a {device_id}")
                return jsonify({"status": "success", "message": f"Comando enviado."})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
        else:
            return jsonify({
                "status": "error", 
                "message": "Dispositivo no conectado.",
                "connected_devices": list(connected_clients.keys())
            }), 404

# --- Punto de inicio del programa ---
if __name__ == "__main__":
    # 1. Iniciar el servidor TCP en un hilo secundario (background).
    tcp_thread = threading.Thread(target=start_tcp_server, daemon=True)
    tcp_thread.start()
    
    # 2. Iniciar el servidor Flask (API web) en el hilo principal.
    #    Este es el proceso que Railway mantendrá vivo.
    print(f"--- SERVIDOR API INICIADO en {HOST}:{API_PORT} ---")
    app.run(host=HOST, port=API_PORT)
