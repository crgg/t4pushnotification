from dotenv import load_dotenv
load_dotenv()
from urllib.parse import quote_plus
import os


class Config:
    APNS_KEY_ID = os.getenv('APNS_KEY_ID')
    APNS_TEAM_ID = os.getenv('APNS_TEAM_ID')
    APNS_AUTH_KEY_PATH = os.getenv('APNS_AUTH_KEY_PATH')
    APNS_TOPIC = os.getenv('APNS_TOPIC')
    APNS_USE_SANDBOX = os.getenv("APNS_USE_SANDBOX", "true").lower() == "true"

    # Authentication Configuration
    AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY")

    AUTH_PASSPHRASE = os.getenv('APP_PASS_PHRASE')
    AUTH_TOKEN_EXPIRY = int(os.getenv("AUTH_TOKEN_EXPIRY", "86400"))  # 24h
    ENCRYPT_KEY = os.getenv('ENCRYPT_KEY')

    # Server Configuration
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    # APNs JWT expiration (seconds)
    JWT_TOKEN_EXPIRY = int(os.getenv("JWT_TOKEN_EXPIRY", "3600"))

    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', '5432'))
    DB_NAME = os.getenv('DB_NAME', 'postgres')
    DB_USER = os.getenv('DB_USER', 'postgres')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL") or (
        f"postgresql+psycopg2://{quote_plus(Config.DB_USER)}:{quote_plus(Config.DB_PASSWORD)}"
        f"@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}"
    )