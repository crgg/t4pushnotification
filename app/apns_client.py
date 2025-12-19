import httpx

from app.config import Config
from pathlib import Path
import logging
import jwt as pyjwt
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
from app.db import DatabaseHandler
import time


db = DatabaseHandler()
class APNsHandler:
    def __init__(self):
        self.key_id = Config.APNS_KEY_ID
        self.team_id = Config.APNS_TEAM_ID
        self.bundle_id = Config.APNS_TOPIC
        self.auth_key = self._load_auth_key()
        self.endpoint = "https://api.sandbox.push.apple.com" if Config.APNS_USE_SANDBOX else "https://api.push.apple.com"
        self.cached_token = None
        self.token_expiry = 0



    def _load_auth_key(self):
        """Load the APNs authentication key from .p8 file"""
        try:
            auth_key_path = Path(Config.APNS_AUTH_KEY_PATH)
            if not auth_key_path.exists():
                logger.error(f"APNs auth key not found at {Config.APNS_AUTH_KEY_PATH}")
                return None

            with open(auth_key_path, 'r') as f:
                key_content = f.read()
                logger.info("APNs authentication key loaded successfully")
                return key_content
        except Exception as e:
            logger.error(f"Error loading APNs auth key: {str(e)}")
            return None

    def save_apns_config(
            self, key_id, team_id, bundle_id,
            p8_filename, environment='sandbox',
            enc_filename=None, enc_alg='AES-256-GCM',
            enc_nonce=None, key_version=1, file_sha256=None
    ):
        try:
            conn = db.get_connection()
            if not conn:
                logger.error("Could not connect to database")
                return False

            cursor = conn.cursor()

            cursor.execute("UPDATE apns_config SET is_active = false")

            cursor.execute("""
                           INSERT INTO apns_config (
                               key_id, team_id, bundle_id, p8_filename, environment, is_active,
                               enc_filename, enc_alg, enc_nonce, key_version, file_sha256
                           ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           """, (
                               key_id, team_id, bundle_id, p8_filename, environment, True,
                               enc_filename, enc_alg, enc_nonce, key_version, file_sha256
                           ))

            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error saving APNs config: {str(e)}")
            return False


    def set_apn_key_active(self, key_id):
        try:
            conn = db.get_connection()
            if not conn:
                logger.error("Could not connect to database")
                return False

            cursor = conn.cursor()

            # Deactivate all previous configs

            cursor.execute("UPDATE apn_keys SET is_active = false")

            # Insert new config
            cursor.execute("""
                           INSERT INTO apn_keys (
                               key_id,  is_active
                           ) VALUES (%s, %s)
                           """, (key_id,True))


            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"✓ APNs config saved: {key_id}")
            return True

        except Exception as e:
            logger.error(f"Error saving APNs config: {str(e)}")
            return False

    def _generate_jwt_token(self):
        if not self.auth_key:
            logger.error("No auth key available for JWT generation")
            return None

        current_time = int(time.time())
        if self.cached_token and current_time < self.token_expiry:
            logger.debug("Using cached JWT token")
            return self.cached_token

        headers = {
            "alg": "ES256",
            "kid": self.key_id,
            "typ": "JWT"
        }

        payload = {
            "iss": self.team_id,
            "iat": current_time
        }

        try:
            auth_key_clean = self.auth_key.strip()

            token = pyjwt.encode(
                payload,
                auth_key_clean,
                algorithm="ES256",
                headers=headers
            )

            if isinstance(token, bytes):
                token = token.decode('utf-8')

            self.cached_token = token
            self.token_expiry = current_time + Config.JWT_TOKEN_EXPIRY - 60

            logger.info(f"New JWT token generated and cached (expires in {Config.JWT_TOKEN_EXPIRY}s)")
            logger.debug(f"JWT Token: {token[:50]}...")
            return token
        except Exception as e:
            logger.error(f"Error generating JWT token: {str(e)}")
            logger.error(f"Key ID: {self.key_id}, Team ID: {self.team_id}")
            return None
    def validate_token(self, device_token):
        if not device_token:
            return False, "Device token is empty"

        clean_token = device_token.replace(" ", "").replace("<", "").replace(">", "")

        if len(clean_token) != 64:
            return False, f"Invalid token length: {len(clean_token)} (expected 64)"

        if not all(c in '0123456789abcdefABCDEF' for c in clean_token):
            return False, "Token contains invalid characters (must be hexadecimal)"

        return True, clean_token



    def send_notification(self, device_token, title, message, badge=None, sound="default",
                          category=None, thread_id=None, data=None, priority="high",
                          collapse_id=None, expiration=None):

        if not self.auth_key:
            return {
                "success": False,
                "error": "APNs authentication key not configured",
                "details": "Please ensure the .p8 file is in the correct location"
            }

        jwt_token = self._generate_jwt_token()
        if not jwt_token:
            return {
                "success": False,
                "error": "Failed to generate JWT token",
                "details": "Check your Key ID, Team ID, and .p8 file format"
            }

        alert = {
            "title": title,
            "body": message
        }

        aps = {
            "alert": alert,
            "sound": sound
        }

        if badge is not None:
            aps["badge"] = badge

        if category:
            aps["category"] = category

        if thread_id:
            aps["thread-id"] = thread_id

        payload = {"aps": aps}

        if data and isinstance(data, dict):
            payload.update(data)

        url = f"{self.endpoint}/3/device/{device_token}"

        headers = {
            "authorization": f"bearer {jwt_token}",
            "apns-topic": self.bundle_id,
            "apns-push-type": "alert",
            "apns-priority": "10" if priority == "high" else "5"
        }

        if collapse_id:
            headers["apns-collapse-id"] = collapse_id

        if expiration is not None:
            headers["apns-expiration"] = str(expiration)
        else:
            headers["apns-expiration"] = "0"

        try:
            with httpx.Client(http2=True, timeout=30.0, verify=True) as client:
                response = client.post(
                    url,
                    headers=headers,
                    json=payload
                )

            if response.status_code == 200:
                logger.info(f"✓ Notification sent successfully to token: {device_token[:8]}...")
                return {
                    "success": True,
                    "message": "Notification sent successfully",
                    "apns_id": response.headers.get("apns-id"),
                    "device_token": device_token[:8] + "..."
                }
            else:
                error_data = {}
                if response.text:
                    try:
                        error_data = response.json()
                    except:
                        pass

                reason = error_data.get("reason", "Unknown error")
                timestamp = error_data.get("timestamp")

                logger.error(f"✗ APNs error: {reason} (status {response.status_code}) for token: {device_token[:8]}...")

                return {
                    "success": False,
                    "error": reason,
                    "status_code": response.status_code,
                    "timestamp": timestamp,
                    "device_token": device_token[:8] + "...",
                    "details": self._get_error_description(reason)
                }

        except httpx.ConnectTimeout:
            logger.error(f"✗ Connection timeout to APNs")
            return {
                "success": False,
                "error": "Connection timeout",
                "details": "Could not connect to APNs servers. Check your internet connection."
            }
        except httpx.ReadTimeout:
            logger.error(f"✗ Read timeout from APNs")
            return {
                "success": False,
                "error": "Read timeout",
                "details": "APNs server did not respond in time"
            }
        except httpx.ConnectError as e:
            logger.error(f"✗ Connection error: {str(e)}")
            return {
                "success": False,
                "error": "Connection error",
                "details": f"Could not connect to APNs: {str(e)}. Check your credentials and network."
            }
        except Exception as e:
            logger.error(f"✗ APNs exception: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "details": "Unexpected error occurred. Check logs for details."
            }

    def _get_error_description(self, reason):
        error_descriptions = {
            "BadDeviceToken": "The device token is invalid. Remove this token from your database.",
            "DeviceTokenNotForTopic": "The device token does not match the specified topic (bundle ID).",
            "Unregistered": "The device token is inactive. Remove this token from your database.",
            "BadCertificate": "The certificate is invalid.",
            "BadCertificateEnvironment": "Certificate/environment mismatch (sandbox vs production).",
            "ExpiredProviderToken": "The provider token (JWT) has expired. Generating new token...",
            "Forbidden": "Request forbidden.",
            "InvalidProviderToken": "The provider token is invalid.",
            "MissingDeviceToken": "No device token specified in the request path.",
            "MissingTopic": "The apns-topic header is missing.",
            "PayloadTooLarge": "The notification payload is too large (max 4KB).",
            "TopicDisallowed": "Pushing to this topic is not allowed.",
            "BadMessageId": "The apns-id value is invalid.",
            "BadExpirationDate": "The apns-expiration value is invalid.",
            "BadPriority": "The apns-priority value is invalid.",
            "MissingProviderToken": "No provider certificate or token specified.",
            "BadPath": "The request path is invalid.",
            "MethodNotAllowed": "The HTTP method is not allowed.",
            "TooManyRequests": "Too many requests sent. Slow down.",
            "IdleTimeout": "Connection idle timeout.",
            "Shutdown": "APNs server is shutting down.",
            "InternalServerError": "APNs internal server error. Retry later.",
            "ServiceUnavailable": "APNs service unavailable. Retry later.",
            "MissingPayload": "The notification payload is empty."
        }
        return error_descriptions.get(reason, "Unknown error. Check APNs documentation.")

