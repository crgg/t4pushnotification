import httpx
import os
import base64
from pathlib import Path
import logging
import jwt as pyjwt
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Config
from app.db import DatabaseHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = DatabaseHandler()


class APNsHandler:
    def __init__(self):
        self.key_id = Config.APNS_KEY_ID
        self.team_id = Config.APNS_TEAM_ID
        self.bundle_id = Config.APNS_TOPIC
        self.auth_key = None
        self.endpoint = "https://api.sandbox.push.apple.com" if Config.APNS_USE_SANDBOX else "https://api.push.apple.com"

        self.cached_token = None
        self.token_expiry = 0

    # ---------- Local path fallback ----------
    def _load_auth_key_from_path(self):
        try:
            auth_key_path = Path(Config.APNS_AUTH_KEY_PATH)
            if not auth_key_path.exists():
                logger.error(f"APNs auth key not found at {Config.APNS_AUTH_KEY_PATH}")
                return None

            with open(auth_key_path, "r", encoding="utf-8") as f:
                key_content = f.read()
                logger.info("APNs authentication key loaded successfully (plaintext path fallback)")
                return key_content
        except Exception as e:
            logger.error(f"Error loading APNs auth key: {str(e)}")
            return None

    # ---------- Encryption helpers ----------
    def _get_enc_key_by_version(self, version: int) -> bytes:
        key_b64 = os.getenv(f"APNS_ENCRYPTION_KEY_B64_V{version}") or os.getenv("APNS_ENCRYPTION_KEY_B64")
        if not key_b64:
            raise RuntimeError("Encryption key not set (APNS_ENCRYPTION_KEY_B64[_Vn])")

        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise RuntimeError("Encryption key must decode to 32 bytes (AES-256)")
        return key

    def _decrypt_aesgcm(self, nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    # ---------- DB load/decrypt active config ----------
    def get_active_apns_config(self):
        conn = db.get_connection()
        if not conn:
            raise RuntimeError("Could not connect to database")

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                id, key_id, team_id, bundle_id, environment,
                enc_alg, enc_nonce, enc_blob, key_version
            FROM apn_keys
            WHERE is_active = true
            ORDER BY id DESC
                LIMIT 1;
            """
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        return row

    def reload_from_active_config(self):
        row = self.get_active_apns_config()
        if not row:
            raise RuntimeError("No active APNs config found in DB")

        (
            _id,
            key_id,
            team_id,
            bundle_id,
            environment,
            enc_alg,
            enc_nonce,
            enc_blob,
            key_version,
        ) = row

        if not enc_nonce or not enc_blob:
            raise RuntimeError("Active config missing encryption metadata (enc_nonce/enc_blob)")

        if isinstance(enc_nonce, memoryview):
            enc_nonce = enc_nonce.tobytes()
        if isinstance(enc_blob, memoryview):
            enc_blob = enc_blob.tobytes()

        if (enc_alg or "").upper() not in {"AES-256-GCM", "AES256GCM", "AESGCM"}:
            raise RuntimeError(f"Unsupported encryption algorithm: {enc_alg}")

        key = self._get_enc_key_by_version(int(key_version or 1))
        p8_bytes = self._decrypt_aesgcm(enc_nonce, enc_blob, key)

        self.auth_key = p8_bytes.decode("utf-8", errors="strict").strip()
        self.key_id = key_id
        self.team_id = team_id
        self.bundle_id = bundle_id

        self.endpoint = (
            "https://api.sandbox.push.apple.com"
            if environment == "sandbox"
            else "https://api.push.apple.com"
        )

        self.cached_token = None
        self.token_expiry = 0

        logger.info(f" Active APNs config loaded from DB (env={environment}, key_id={key_id})")

    def has_active_config(self) -> bool:
            try:
                conn = db.get_connection()
                if not conn:
                    return False

                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM apn_keys WHERE is_active = true LIMIT 1"
                )
                exists = cursor.fetchone() is not None
                cursor.close()
                conn.close()
                return exists

            except Exception:
                return False

    # ---------- Persist config ----------
    def save_apns_config(
            self,
            key_id,
            team_id,
            bundle_id,
            p8_filename,
            environment="sandbox",
            enc_alg="AES-256-GCM",
            enc_nonce=None,
            enc_filename=None,
            enc_blob=None,
            key_version=1,
            file_sha256=None,
            company_id=None,
    ):
        try:
            conn = db.get_connection()
            if not conn:
                return False

            cursor = conn.cursor()

            cursor.execute("UPDATE apn_keys SET is_active = false")

            cursor.execute("""
                           INSERT INTO apn_keys (
                               key_id, team_id, bundle_id, p8_filename, environment, is_active,
                               enc_alg, enc_nonce, enc_blob, key_version, file_sha256,enc_filename, company_id
                           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                           """, (
                               key_id, team_id, bundle_id, p8_filename, environment, True,
                               enc_alg, enc_nonce, enc_blob, key_version, file_sha256, enc_filename, company_id
                           ))

            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error saving APNs config: {e}")
            return False

    def list_apn_keys(self):
        conn = db.get_connection()
        if not conn:
            raise RuntimeError("Could not connect to database")

        cursor = conn.cursor()
        cursor.execute("""
                       SELECT
                           id, key_id, team_id, bundle_id,company_id, environment, is_active, created_at
                       FROM apn_keys
                       ORDER BY created_at DESC, id DESC
                       """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows

    def activate_apns_config_by_bundle(self, bundle_id: str, environment: str | None = None) -> bool:
        conn = db.get_connection()
        if not conn:
            raise RuntimeError("Could not connect to database")

        cursor = conn.cursor()

        if environment:
            cursor.execute("""
                           SELECT id
                           FROM apn_keys
                           WHERE bundle_id = %s AND environment = %s
                               LIMIT 1
                           """, (bundle_id, environment))
        else:
            cursor.execute("""
                           SELECT id
                           FROM apn_keys
                           WHERE bundle_id = %s
                               LIMIT 1
                           """, (bundle_id,))

        row = cursor.fetchone()
        if not row:
            cursor.close()
            conn.close()
            return False

        try:
            cursor.execute("BEGIN")
            cursor.execute("UPDATE apn_keys SET is_active = false WHERE is_active = true")

            if environment:
                cursor.execute("""
                               UPDATE apn_keys
                               SET is_active = true
                               WHERE id = (
                                   SELECT id
                                   FROM apn_keys
                                   WHERE bundle_id = %s AND environment = %s
                                   ORDER BY created_at DESC, id DESC
                                   LIMIT 1
                                   )
                               """, (bundle_id, environment))
            else:
                cursor.execute("""
                               UPDATE apn_keys
                               SET is_active = true
                               WHERE id = (
                                   SELECT id
                                   FROM apn_keys
                                   WHERE bundle_id = %s
                                   ORDER BY created_at DESC, id DESC
                                   LIMIT 1
                                   )
                               """, (bundle_id,))

            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception:
            conn.rollback()
            cursor.close()
            conn.close()
            raise

    # ---------- JWT + APNs ----------
    def _generate_jwt_token(self):
        if not self.auth_key:
            logger.error("No auth key available for JWT generation")
            return None

        current_time = int(time.time())
        if self.cached_token and current_time < self.token_expiry:
            return self.cached_token

        headers = {"alg": "ES256", "kid": self.key_id, "typ": "JWT"}
        payload = {"iss": self.team_id, "iat": current_time}

        try:
            token = pyjwt.encode(payload, self.auth_key, algorithm="ES256", headers=headers)
            if isinstance(token, bytes):
                token = token.decode("utf-8")

            self.cached_token = token
            self.token_expiry = current_time + Config.JWT_TOKEN_EXPIRY - 60
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
        if not all(c in "0123456789abcdefABCDEF" for c in clean_token):
            return False, "Token contains invalid characters (must be hexadecimal)"
        return True, clean_token

    def send_notification(
            self,
            device_token,
            title,
            message,
            badge=None,
            sound="default",
            category=None,
            thread_id=None,
            data=None,
            priority="high",
            collapse_id=None,
            expiration=None,
            pushtype="alert",
    ):
        if not self.auth_key:
            return {
                "success": False,
                "error": "APNs authentication key not configured",
                "details": "Upload a key via /upload/key or configure APNS_AUTH_KEY_PATH fallback",
            }

        jwt_token = self._generate_jwt_token()
        if not jwt_token:
            return {
                "success": False,
                "error": "Failed to generate JWT token",
                "details": "Check your Key ID, Team ID, and decrypted .p8 validity",
            }

        if pushtype == "alert" :
            payload = {
                "aps": {
                    "alert": {"title": title, "body": message},
                    "sound": sound,
                }
            }
        else:
            payload = {
                "aps" : {
                    "content-available" : 1
                },
                "body" : message,
                "category" : category
            }

        if badge is not None:
            payload["aps"]["badge"] = badge
        if category:
            payload["aps"]["category"] = category
        if thread_id:
            payload["aps"]["thread-id"] = thread_id
        if data and isinstance(data, dict):
            payload.update(data)

        url = f"{self.endpoint}/3/device/{device_token}"

        headers = {
            "authorization": f"bearer {jwt_token}",
            "apns-topic": self.bundle_id,
            "apns-push-type": pushtype,
            "apns-priority": "10" if priority == "high" else "5",
            "apns-expiration": str(expiration) if expiration is not None else "0",
        }

        if collapse_id:
            headers["apns-collapse-id"] = collapse_id

        try:
            with httpx.Client(http2=True, timeout=30.0, verify=True) as client:
                response = client.post(url, headers=headers, json=payload)

            if response.status_code == 200:
                return {
                    "success": True,
                    "message": "Notification sent successfully",
                    "apns_id": response.headers.get("apns-id"),
                    "device_token": device_token[:8] + "...",
                }

            error_data = {}
            if response.text:
                try:
                    error_data = response.json()
                except Exception:
                    pass

            reason = error_data.get("reason", "Unknown error")
            timestamp = error_data.get("timestamp")

            return {
                "success": False,
                "error": reason,
                "status_code": response.status_code,
                "timestamp": timestamp,
                "device_token": device_token[:8] + "...",
                "details": self._get_error_description(reason),
            }

        except httpx.ConnectTimeout:
            return {"success": False, "error": "Connection timeout", "details": "Could not connect to APNs servers."}
        except httpx.ReadTimeout:
            return {"success": False, "error": "Read timeout", "details": "APNs server did not respond in time"}
        except httpx.ConnectError as e:
            return {"success": False, "error": "Connection error", "details": f"Could not connect to APNs: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e), "details": "Unexpected error occurred."}

    def assign_project(self, project_id, key_id):
        try:
            conn = db.get_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute("""
                           UPDATE apn_keys
                           SET project_id = %s where id = %s
                           """,(project_id, key_id))

            conn.commit()
            cursor.close()
            conn.close()

            return True
        except Exception as e:
            logger.error(f"Error in the project assignent: {e}")
            return False

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
            "MissingPayload": "The notification payload is empty.",
        }
        return error_descriptions.get(reason, "Unknown error. Check APNs documentation.")