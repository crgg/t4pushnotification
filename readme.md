# 1. Generar la llave de encriptaciopn
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
# Copiar y agregar al .env como APNS_ENCRYPTION_KEY_B64

# 2. Tirar Docker Compose 
docker-compose up -d

# 3. Checkear que hayan logs.
docker-compose logs -f apns-server