import struct
from datetime import datetime

class JT808Decoder:
    """
    Decodificador de paquetes basado en el protocolo JT/T 808 y extensiones propietarias
    para el mensaje de Reporte de Posición (0x0200).
    
    Diseñado para ser robusto frente a inconsistencias de longitud en el bloque 0xEB.
    """

    def __init__(self):
        # Mapeo de valores de estado de posición (Status bits)
        self.status_map = {
            0: "ACC: Apagado (OFF)",
            1: "ACC: Encendido (ON)",
        }
        
        # Corrección de longitud forzada para el bloque 0xEB (Información Extendida Propietaria).
        # Esto corrige las inconsistencias de longitud observadas en el protocolo del dispositivo.
        self.eb_field_lengths = {
            0x0089: 6,   # Estado extendido
            0x00C5: 6,   # Alarma extendida
            0x002D: 2,   # Voltaje (Se corrige a 2 bytes de valor)
            0x00A8: 1,   # Porcentaje de batería (Se corrige a 1 byte de valor)
            0x00D5: 15,  # IMEI
            0x00B9: -1   # Información WiFi (longitud variable, se consume el resto)
        }

    def _hex_to_bytes(self, hex_string):
        """Convierte una cadena hexadecimal en un objeto bytes."""
        try:
            return bytes.fromhex(hex_string)
        except ValueError:
            return b''

    def _des_escape(self, hex_body):
        """
        Realiza la des-escapación de la carga útil del paquete.
        7D 01 -> 7D, 7D 02 -> 7E
        """
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
        """Decodifica un campo BCD."""
        return bcd_bytes.hex()

    def _decode_position_status(self, status_dword):
        """Decodifica los bits de estado de la posición."""
        acc_status = self.status_map[status_dword & 0b1]
        pos_bit = (status_dword >> 1) & 0b1
        pos_status = "Posicionado" if pos_bit == 1 else "No Posicionado"

        return {
            "RAW": f"0x{status_dword:08X}",
            "ACC": acc_status,
            "Posicionamiento": pos_status,
        }

    def _decode_time(self, bcd_bytes):
        """Decodifica la hora BCD (YYMMDDhhmmss)."""
        bcd_str = self._decode_bcd(bcd_bytes)
        try:
            year = int(bcd_str[0:2]) + 2000
            month = int(bcd_str[2:4])
            day = int(bcd_str[4:6])
            hour = int(bcd_str[6:8])
            minute = int(bcd_str[8:10])
            second = int(bcd_str[10:12])
            return datetime(year, month, day, hour, minute, second).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Fecha/Hora Inválida"

    def _format_eb_value(self, field_id, value_bytes):
        """Formatea los valores conocidos del bloque propietario (0xEB)."""
        value_hex = value_bytes.hex()
        
        if field_id == 0x002D and len(value_bytes) >= 2: # Voltaje
            voltage_mv = struct.unpack('>H', value_bytes[0:2])[0]
            voltage_v = voltage_mv / 1000.0
            return f"{voltage_v:.2f} V ({voltage_mv} mV)"

        if field_id == 0x00A8 and len(value_bytes) >= 1: # Porcentaje de Batería
            battery_perc = value_bytes[0]
            return f"{battery_perc}%"
        
        if field_id == 0x00D5: # IMEI
            imei = value_bytes.decode('ascii', errors='ignore').strip('\x00')
            return imei
        
        if field_id == 0x00B9: # Información WiFi
            try:
                wifi_data = value_bytes.decode('ascii', errors='ignore')
                return wifi_data
            except:
                return f"RAW: {value_hex}"
        
        return f"RAW: {value_hex}"

    def decode_proprietary_eb(self, eb_bytes):
        """Decodifica el bloque de Información Extendida Propietaria (0xEB)."""
        results = {}
        ptr = 0
        
        EB_HEADER_LEN = 15
        if len(eb_bytes) < EB_HEADER_LEN:
            results["ERROR_HEADER"] = "Longitud insuficiente para encabezado EB."
            return results
        
        ptr += EB_HEADER_LEN # Saltar el encabezado
        
        while ptr < len(eb_bytes):
            try:
                if ptr + 4 > len(eb_bytes):
                     results["ERROR_BREAK"] = f"Datos insuficientes para leer ID/Longitud en posición {ptr}."
                     break

                field_len_raw, field_id = struct.unpack('>HH', eb_bytes[ptr:ptr+4])
                ptr += 4
                
                value_len = self.eb_field_lengths.get(field_id, field_len_raw)
                
                if field_id == 0x00B9:
                    value_len = len(eb_bytes) - ptr
                
                if ptr + value_len > len(eb_bytes):
                    results["ERROR_BREAK"] = f"Desbordamiento en ID 0x{field_id:04X}. Longitud valor: {value_len}. Rompiendo."
                    break

                value_bytes = eb_bytes[ptr:ptr + value_len]
                ptr += value_len
                
                field_name = {
                    0x0089: "Estado_Extendido",
                    0x00C5: "Alarma_Extendida",
                    0x002D: "Voltaje",
                    0x00A8: "Bateria_Porcentaje",
                    0x00D5: "IMEI",
                    0x00B9: "WiFi_Data",
                }.get(field_id, f"ID_0x{field_id:04X}_Desconocido")

                results[field_name] = self._format_eb_value(field_id, value_bytes)

            except Exception as e:
                results["ERROR_UNKNOWN"] = f"Error al decodificar EB en {ptr}: {e}"
                break
        
        return results

    def decode_tlv_additional_info(self, body_bytes):
        """Decodifica los bloques de Información Adicional (TLV)."""
        results = {}
        ptr = 0
        
        while ptr < len(body_bytes):
            try:
                if ptr + 2 > len(body_bytes):
                    results["ERROR_TLV"] = f"Fin inesperado al leer ID/Len en {ptr}."
                    break
                    
                field_id = body_bytes[ptr]
                field_len = body_bytes[ptr + 1]
                ptr += 2
                
                if ptr + field_len > len(body_bytes):
                    results["ERROR_TLV"] = f"Longitud de 0x{field_id:02X} ({field_len}) excede el remanente. Rompiendo."
                    break

                value_bytes = body_bytes[ptr:ptr + field_len]
                ptr += field_len
                
                if field_id == 0x30:
                    results["Fuerza_Senal"] = value_bytes[0]
                elif field_id == 0x33:
                    mode = value_bytes[0]
                    results["Modo_Trabajo"] = "Ultra-larga duración" if mode == 1 else f"Desconocido (RAW: {mode})"
                elif field_id == 0xEB:
                    results["Info_Extendida"] = self.decode_proprietary_eb(value_bytes)
                else:
                    results[f"ID_Adicional_0x{field_id:02X}"] = value_bytes.hex()

            except Exception as e:
                results["ERROR_TLV_GENERAL"] = f"Error al decodificar TLV: {e}"
                break
                
        return results

    def decode_position_report(self, raw_hex_data: str) -> dict:
        """Procesa y decodifica el paquete completo de reporte de posición (0x0200)."""
        output = {"status": "FAILURE"}

        if not raw_hex_data.startswith('7e') or not raw_hex_data.endswith('7e') or len(raw_hex_data) < 10:
            output["error"] = "Trama HEX inválida (falta flag 0x7E o es demasiado corta)."
            return output
        
        escaped_body = raw_hex_data[2:-4] 
        checksum_hex = raw_hex_data[-4:-2]
        
        descaped_body_hex = self._des_escape(escaped_body)
        descaped_body_bytes = self._hex_to_bytes(descaped_body_hex)
        
        if not descaped_body_bytes:
            output["error"] = "Fallo al convertir la trama des-escapada a bytes."
            return output
        
        calculated_checksum = self._xor_checksum(descaped_body_bytes)
        expected_checksum = int(checksum_hex, 16)
        
        output["checksum"] = {"calculated": f"0x{calculated_checksum:02X}", "expected": f"0x{expected_checksum:02X}"}
        if calculated_checksum != expected_checksum:
            output["warning"] = "Checksum NO OK."
        
        ptr = 0
        try:
            # Encabezado (12 bytes)
            if len(descaped_body_bytes) < 12: raise Exception("Cuerpo de mensaje demasiado corto para el encabezado.")
            msg_id, body_len, terminal_phone_bcd, serial_num = struct.unpack('>HH6sH', descaped_body_bytes[ptr:ptr+12])
            ptr += 12
            
            terminal_id = self._decode_bcd(terminal_phone_bcd)
            
            output["header"] = {
                "message_id": f"0x{msg_id:04X}",
                "terminal_id": terminal_id,
                "serial_number": serial_num
            }
            
            if msg_id != 0x0200:
                output["error"] = f"ID de Mensaje inesperado: 0x{msg_id:04X}"
                return output

            # Posición (28 bytes)
            if ptr + 28 > len(descaped_body_bytes): raise Exception("Cuerpo de mensaje demasiado corto para el bloque de posición.")
                
            (alarm_flag, status_dword, latitude_raw, longitude_raw, altitude, 
             speed, direction, time_bcd) = struct.unpack('>IIIIHHH6s', descaped_body_bytes[ptr:ptr+28])
            ptr += 28

            latitude = latitude_raw / 1000000.0
            longitude = longitude_raw / 1000000.0
            
            output["position"] = {
                "alarm_raw": f"0x{alarm_flag:08X}",
                "status": self._decode_position_status(status_dword),
                "latitude": latitude,
                "longitude": longitude,
                "altitude": altitude,
                "speed": speed,
                "direction": direction,
                "report_time": self._decode_time(time_bcd)
            }

            # Información Adicional (TLV) - Usamos el resto del buffer
            additional_info_bytes = descaped_body_bytes[ptr:] 
            output["additional_info"] = self.decode_tlv_additional_info(additional_info_bytes)
            
            output["status"] = "SUCCESS"

        except Exception as e:
            output["error"] = f"Fallo crítico al decodificar la trama: {e}"
            output["status"] = "ERROR_PARSING"
            
        return output

    def create_response_8001(self, original_message_id: int, terminal_id_bcd_hex: str, original_serial_number: int, result: int = 0) -> str:
        """
        Genera la trama de respuesta 0x8001 (Respuesta general de la plataforma).
        """
        # Cuerpo de la respuesta: ID Mensaje Original (WORD), Serial Original (WORD), Resultado (BYTE)
        body_data = struct.pack('>HBH', original_message_id, result, original_serial_number)
        
        terminal_id_bytes = self._hex_to_bytes(terminal_id_bcd_hex)
        response_serial = original_serial_number 
        
        # Encabezado: ID Mensaje (WORD 0x8001), Longitud Cuerpo (WORD), ID Terminal (BCD 6 bytes), Serial (WORD)
        response_header = struct.pack('>HH6sH', 0x8001, len(body_data), terminal_id_bytes, response_serial)
        
        response_trama_data = response_header + body_data

        checksum = self._xor_checksum(response_trama_data)
        response_hex = f"7e{response_trama_data.hex()}{checksum:02x}7e"
        
        return response_hex.upper()
