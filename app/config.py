import secrets
import os
class Config:
    APNS_KEY_ID = os.getenv('APNS_KEY_ID')
    APNS_TEAM_ID = os.getenv('APNS_TEAM_ID')
    APNS_AUTH_KEY_PATH = os.getenv('APNS_AUTH_KEY_PATH')
    APNS_TOPIC = os.getenv('APNS_TOPIC')
    APNS_USE_SANDBOX = True

    # Authentication Configuration
    AUTH_SECRET_KEY = secrets.token_urlsafe(32)  # Generate a secure secret key
    AUTH_PASSPHRASE = os.getenv('APP_PASS_PHRASE')
    AUTH_TOKEN_EXPIRY = 86400  # 24 hours in seconds
    ENCRYPT_KEY = os.getenv('ENCRYPT_KEY')

    # Server Configuration
    PORT = 5000
    DEBUG = True

    # Token expiration time (in seconds) - APNs tokens are valid for 1 hour
    JWT_TOKEN_EXPIRY = 3600  # 1 hour

    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT')
    DB_NAME = os.getenv('DB_NAME')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')

class Settings:
    DATABASE_URL = os.getenv('DATABASE_URL')