import struct
import re
from datetime import datetime

class JT808Decoder:
    """
    Decodificador de paquetes basado en el protocolo JT/T 808 y extensiones propietarias
    para el mensaje de Reporte de Posición (0x0200).
    """

    def __init__(self):
        # Mapeo de valores de estado de posición (Status bits)
        self.status_map = {
            0: "ACC: Apagado (OFF)",
            1: "ACC: Encendido (ON)",
            2: "Posicionamiento: No Posicionado",
            3: "Posicionamiento: Posicionado",
        }
        
        # Longitudes de campo específicas para el bloque propietario (0xEB)
        # Esto es necesario debido a inconsistencias observadas en el protocolo.
        self.eb_field_lengths = {
            0x0089: 6,   # Estado extendido
            0x00C5: 6,   # Alarma extendida
            0x002D: 2,   # Voltaje (Se corrige de 4 a 2 bytes de valor)
            0x00A8: 1,   # Porcentaje de batería (Se corrige de 3/4 a 1 byte de valor)
            0x00D5: 15,  # IMEI
            0x00B9: -1   # Información WiFi (longitud variable, se consume el resto del paquete)
        }

    def _hex_to_bytes(self, hex_string):
        """Convierte una cadena hexadecimal en un objeto bytes."""
        return bytes.fromhex(hex_string)

    def _des_escape(self, hex_body):
        """
        Realiza la des-escapación de la carga útil del paquete.
        7D 01 -> 7D
        7D 02 -> 7E
        """
        # Expresiones regulares para manejar los reemplazos
        hex_body = hex_body.replace('7d01', '7d')
        hex_body = hex_body.replace('7d02', '7e')
        return hex_body

    def _xor_checksum(self, data_bytes):
        """Calcula el checksum XOR de los bytes de la trama."""
        checksum = 0
        for byte in data_bytes:
            checksum ^= byte
        return checksum

    def _decode_bcd(self, bcd_bytes):
        """Decodifica un campo BCD (como la hora o el número de teléfono)."""
        return bcd_bytes.hex()

    def _decode_position_status(self, status_dword):
        """Decodifica los bits de estado de la posición."""
        acc_status = self.status_map[status_dword & 0b1]
        pos_status = self.status_map[(status_dword >> 1) & 0b1] + 'Posicionado' if (status_dword >> 1) & 0b1 else 'No Posicionado'

        return {
            "RAW": f"0x{status_dword:08X}",
            "ACC": acc_status,
            "Posicionamiento": pos_status,
        }

    def _decode_time(self, bcd_bytes):
        """Decodifica la hora BCD (YYMMDDhhmmss) a un objeto datetime."""
        bcd_str = self._decode_bcd(bcd_bytes)
        year = int(bcd_str[0:2]) + 2000
        month = int(bcd_str[2:4])
        day = int(bcd_str[4:6])
        hour = int(bcd_str[6:8])
        minute = int(bcd_str[8:10])
        second = int(bcd_str[10:12])
        try:
            # Nota: El dispositivo reporta en UTC+8.
            return datetime(year, month, day, hour, minute, second)
        except ValueError:
            return "Fecha/Hora Inválida"

    def decode_proprietary_eb(self, eb_bytes):
        """
        Decodifica el bloque de Información Extendida Propietaria (0xEB).
        Estructura asumida: [Length(WORD) | ID(WORD) | Value(Length bytes)]
        """
        results = {}
        ptr = 0

        # 1. Saltamos el encabezado propietario de 15 bytes
        EB_HEADER_LEN = 15
        if len(eb_bytes) < EB_HEADER_LEN:
            results["ERROR_HEADER"] = "Longitud insuficiente para encabezado EB."
            return results
        
        results["Encabezado Propietario (RAW)"] = eb_bytes[0:EB_HEADER_LEN].hex()
        ptr += EB_HEADER_LEN

        # 2. Decodificación de campos TLV internos
        while ptr < len(eb_bytes):
            try:
                # La estructura es inestable. Intentamos leer Longitud (WORD) e ID (WORD).
                # Usamos >H para Big-Endian WORD (2 bytes)
                field_len_raw, field_id = struct.unpack('>HH', eb_bytes[ptr:ptr+4])
                ptr += 4
                
                # Determinamos la longitud real del valor (reparación del protocolo)
                if field_id in self.eb_field_lengths and self.eb_field_lengths[field_id] != -1:
                    value_len = self.eb_field_lengths[field_id]
                else:
                    # Usamos la longitud reportada por el campo, pero solo si es razonable
                    value_len = field_len_raw
                
                # Si el campo es 0x00B9 (Wi-Fi), consume el resto del paquete
                if field_id == 0x00B9:
                    value_len = len(eb_bytes) - ptr
                
                if ptr + value_len > len(eb_bytes):
                    results["ERROR_BREAK"] = f"Desbordamiento de buffer en ID 0x{field_id:04X}. Longitud de valor reportada: {field_len_raw}, Consumida: {value_len}, Restante: {len(eb_bytes) - ptr}. Rompiendo ciclo."
                    break

                value_bytes = eb_bytes[ptr:ptr + value_len]
                ptr += value_len

                results[f"ID 0x{field_id:04X}"] = self._format_eb_value(field_id, value_bytes)

            except struct.error:
                results["ERROR_STRUCT"] = f"Fallo de empaquetado/desempaquetado en la posición {ptr}. Fin inesperado de datos."
                break
            except Exception as e:
                results["ERROR_UNKNOWN"] = f"Error inesperado al decodificar: {e}"
                break
        
        return results

    def _format_eb_value(self, field_id, value_bytes):
        """Formatea los valores conocidos del bloque propietario (0xEB)."""
        value_hex = value_bytes.hex()
        
        if field_id == 0x0089: # Estado Extendido
            # FFFFFFFF0006 -> La documentación sugiere 4 bytes de estado.
            dword = struct.unpack('>I', value_bytes[0:4])[0]
            status_str = f"Bitmask: 0x{dword:08X}"
            # (Ej. bit3: No Posicionamiento, bit4: Posicionamiento WiFi)
            return f"Estado Extendido (RAW): {value_hex} | {status_str}"
        
        elif field_id == 0x00C5: # Alarma Extendida
            dword = struct.unpack('>I', value_bytes[0:4])[0]
            # bitmask: 0xFFFFFFF7. bit3: Posicionamiento WiFi
            return f"Alarma Extendida (RAW): {value_hex} | Bitmask: 0x{dword:08X}"

        elif field_id == 0x002D: # Voltaje
            if len(value_bytes) >= 2:
                # Voltaje en mV (Ej. 11F7 = 4600 mV)
                voltage_mv = struct.unpack('>H', value_bytes[0:2])[0]
                voltage_v = voltage_mv / 1000.0
                return f"Voltaje: {voltage_v:.2f} V ({voltage_mv} mV) (RAW: {value_hex})"
            return f"Voltaje (RAW): {value_hex}"

        elif field_id == 0x00A8: # Porcentaje de Batería
            if len(value_bytes) >= 1:
                battery_perc = value_bytes[0]
                return f"Batería: {battery_perc}% (RAW: {value_hex})"
            return f"Batería (RAW): {value_hex}"
        
        elif field_id == 0x00D5: # IMEI
            # Se decodifica de HEX a cadena ASCII
            imei = value_bytes.decode('ascii', errors='ignore')
            return f"IMEI: {imei} (RAW: {value_hex})"
        
        elif field_id == 0x00B9: # Información WiFi
            # Decodificación de la cadena de MAC/RSSI
            try:
                wifi_data = value_bytes.decode('ascii', errors='ignore')
                return f"Datos WiFi: {wifi_data}"
            except:
                return f"Datos WiFi (RAW): {value_hex}"

        return f"Valor RAW: {value_hex}"

    def decode_tlv_additional_info(self, body_bytes):
        """
        Decodifica los bloques de Información Adicional (TLV - Tag/Length/Value)
        del cuerpo principal del mensaje (ID 1 byte, Longitud 1 byte).
        """
        results = {}
        ptr = 0
        
        while ptr < len(body_bytes):
            try:
                # ID (BYTE) y Longitud (BYTE)
                field_id = body_bytes[ptr]
                field_len = body_bytes[ptr + 1]
                ptr += 2
                
                if ptr + field_len > len(body_bytes):
                    results["ERROR"] = f"Longitud de campo 0x{field_id:02X} excede el cuerpo de la trama."
                    break

                value_bytes = body_bytes[ptr:ptr + field_len]
                ptr += field_len
                
                # Manejo de IDs conocidos
                if field_id == 0x30: # Fuerza de señal inalámbrica
                    value = value_bytes[0]
                    results["Fuerza de Señal Inalámbrica (0x30)"] = value
                
                elif field_id == 0x33: # Modo de Trabajo
                    mode = value_bytes[0]
                    mode_desc = "Modo de Ultra-larga duración (Ahorro de energía)" if mode == 1 else f"Modo Desconocido (RAW: {mode})"
                    results["Modo de Trabajo (0x33)"] = mode_desc
                
                elif field_id == 0xEB: # Información Extendida Propietaria (¡El bloque problemático!)
                    results["Info. Extendida Propietaria (0xEB)"] = self.decode_proprietary_eb(value_bytes)

                else:
                    results[f"ID Adicional Desconocido (0x{field_id:02X})"] = value_bytes.hex()

            except IndexError:
                results["ERROR"] = f"Fin inesperado de datos al decodificar TLV en la posición {ptr}."
                break
            except Exception as e:
                results["ERROR"] = f"Error al decodificar bloque TLV: {e}"
                break
                
        return results

    def decode_position_report(self, raw_hex_data):
        """Procesa y decodifica el paquete completo de reporte de posición."""
        output = {"Estado": "FALLO"}

        # 1. Des-escapar la trama completa y extraer el cuerpo
        if not raw_hex_data.startswith('7e') or not raw_hex_data.endswith('7e'):
            output["ERROR"] = "La trama no comienza ni termina con el flag 0x7E."
            return output
        
        # Extraer el cuerpo (excluyendo flags de inicio/fin y checksum)
        escaped_body = raw_hex_data[2:-4] 
        checksum_hex = raw_hex_data[-4:-2]
        
        descaped_body_hex = self._des_escape(escaped_body)
        descaped_body_bytes = self._hex_to_bytes(descaped_body_hex)
        
        # 2. Validación de Checksum
        calculated_checksum = self._xor_checksum(descaped_body_bytes)
        expected_checksum = int(checksum_hex, 16)
        
        output["Checksum"] = f"Calculado: 0x{calculated_checksum:02X}, Esperado: 0x{expected_checksum:02X}"
        if calculated_checksum != expected_checksum:
            output["ERROR"] = "Checksum NO OK. La trama está dañada o la des-escapación falló."
            output["Estado"] = "ERROR_CHECKSUM"
            # Continuamos el parsing solo para depuración
        
        ptr = 0
        try:
            # 3. Decodificación del Encabezado (JT/T 808-like)
            msg_id, body_len, terminal_phone_bcd, serial_num = struct.unpack('>HH6sH', descaped_body_bytes[ptr:ptr+12])
            ptr += 12
            
            output["ID Mensaje"] = f"0x{msg_id:04X}"
            output["Longitud Cuerpo"] = body_len
            output["Teléfono Terminal (BCD)"] = self._decode_bcd(terminal_phone_bcd)
            output["Número de Serie"] = serial_num
            
            if msg_id != 0x0200:
                output["ERROR"] = f"Mensaje ID 0x{msg_id:04X} no soportado (esperado 0x0200)."
                return output

            # 4. Decodificación del Bloque de Posición (RAW: 28 bytes)
            # Alarm Flag (DWORD), Status (DWORD), Latitude (DWORD), Longitude (DWORD), Altitude (WORD), 
            # Speed (WORD), Direction (WORD), Time (BCD 6 bytes)
            (alarm_flag, status_dword, latitude_raw, longitude_raw, altitude, 
             speed, direction, time_bcd) = struct.unpack('>IIIIHHH6s', descaped_body_bytes[ptr:ptr+28])
            ptr += 28

            # Conversión de Lat/Lon (1/10^6 grado)
            latitude = latitude_raw / 1000000.0
            longitude = longitude_raw / 1000000.0
            
            output["Posicionamiento Básico"] = {
                "Alarma (RAW)": f"0x{alarm_flag:08X}",
                "Estado": self._decode_position_status(status_dword),
                "Latitud": f"{latitude:.6f} grados",
                "Longitud": f"{longitude:.6f} grados",
                "Altitud": altitude,
                "Velocidad": speed,
                "Dirección": direction,
                "Hora Reporte (UTC+8)": self._decode_time(time_bcd).strftime("%Y-%m-%d %H:%M:%S")
            }

            # 5. Decodificación de Información Adicional (TLV)
            additional_info_bytes = descaped_body_bytes[ptr:ptr + body_len - 28 - 12] # Longitud total - Header - Posicionamiento
            output["Información Adicional (TLV)"] = self.decode_tlv_additional_info(additional_info_bytes)
            
            output["Estado"] = "OK"

        except struct.error:
            output["ERROR"] = "Error de estructura (longitud de bytes incompleta o incorrecta)."
            output["Estado"] = "ERROR_STRUCT"
        except Exception as e:
            output["ERROR"] = f"Fallo al decodificar: {e}"
            output["Estado"] = "ERROR_GENERAL"
            
        return output

# --- Datos de Prueba ---
# El "Hex Crudo" proporcionado por el usuario, sin los 7e de inicio y fin.
# Lo usaremos para que el decodificador haga la des-escapación y checksum.
RAW_HEX_DATA = "7e020000df0870771382060020000000000000000c00b87d01440497da5d00000000000025092920060801040000000030011a31011132020129330101ebae000c00b28951064012473110652f00060089ffffffff000600c5fffffff70004002d11f7000300a864001100d5383638333837303737313338323036007000b90532413a34373a33443a34353a443341422c2d35342c44433a36323a37393a35343a30393a44452c2d35322c30453a38343a43363a37373a36463a33432c2d35382c30433a30453a763945423a37302c2d35382c41433a38343a43363a37373a36463a33432c2d35399a7e"

decoder = JT808Decoder()
parsed_data = decoder.decode_position_report(RAW_HEX_DATA)

# Imprimir el resultado de forma legible
import json
print("--- RESULTADO DECODIFICACIÓN REESTRUCTURADA ---")
print(json.dumps(parsed_data, indent=4, ensure_ascii=False))

# Generar la respuesta 0x8001
# ID Mensaje: 0x8001
# Longitud: 0x0005 (5 bytes)
# Teléfono Terminal: 087077138206
# Serial del mensaje original: 32 (0x0020)
# Resultado: 0 (Éxito)
response_body = struct.pack('>H6sBH', 0x0200, b'\x08p\x77\x13\x82\x06', 32, 0)
response_body_hex = response_body.hex()

checksum = decoder._xor_checksum(response_body)
response_hex = f"7e80010005{response_body_hex}{checksum:02x}7e"
print("\n--- RESPUESTA DE PLATAFORMA (0x8001) ---")
print(f"Trama RAW HEX: {response_hex.upper()}")
