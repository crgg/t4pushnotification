"""
iOS Push Notification Server (APNs)
Handles Apple Push Notification service exclusively

Requirements:
pip install flask PyJWT cryptography httpx[http2]
"""

from flask import Flask, request, jsonify
import jwt as pyjwt  # Renamed to avoid confusion with APNs JWT
import time
from datetime import datetime, timedelta
from app.config import Config, Settings
import logging
from functools import wraps
import re
import os, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.apns_client import APNsHandler
from app.db import DatabaseHandler
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



# ==================== Helpers ====================
ALLOWED_ENVIRONMENTS = {"sandbox", "production"}

def _sanitize_token(value: str) -> str:
    """Trim and remove surrounding whitespace; keep as-is otherwise."""
    return (value or "").strip()

def _is_valid_key_id(key_id: str) -> bool:
    # Apple Key ID is typically 10 chars alphanumeric
    return bool(re.fullmatch(r"[A-Z0-9]{10}", key_id or ""))

def _is_valid_team_id(team_id: str) -> bool:
    # Apple Team ID is typically 10 chars alphanumeric
    return bool(re.fullmatch(r"[A-Z0-9]{10}", team_id or ""))

def _is_valid_bundle_id(bundle_id: str) -> bool:
    # Simple bundle id validation: com.company.app (allow letters, digits, dash, underscore, dot)
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", bundle_id or ""))

def _ensure_upload_dir(upload_dir: str) -> None:
    os.makedirs(upload_dir, exist_ok=True)

def _safe_p8_filename(key_id: str) -> str:
    # deterministic, avoids user-provided filename
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"AuthKey_{key_id}_{ts}.p8"


def get_enc_key_and_version():
    key_b64 = os.getenv("APNS_ENCRYPTION_KEY_B64")
    if not key_b64:
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 is not set")

    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 must decode to 32 bytes (AES-256)")

    version = int(os.getenv("APNS_KEY_VERSION", "1"))
    return key, version

def encrypt_bytes_aesgcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)  # 96-bit nonce (recommended)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext includes auth tag
    return nonce, ciphertext

def decrypt_bytes_aesgcm(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ==================== Authentication Decorator ====================
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({
                'status': False,
                'message': 'Authentication required'
            }), 401

        try:
            pyjwt.decode(
                token,
                Config.AUTH_SECRET_KEY,
                algorithms=['HS256']
            )

        except pyjwt.ExpiredSignatureError:
            return jsonify({
                'status': False,
                'message': 'Token expired'
            }), 401
        except pyjwt.InvalidTokenError:
            return jsonify({
                'status': False,
                'message': 'Invalid token'
            }), 401

        return f(*args, **kwargs)

    return decorated_function

# ==================== APNs Handler ====================
apns = APNsHandler()
db = DatabaseHandler()

# ==================== API Routes ====================
@app.route('/debug/jwt', methods=['GET'])
@require_auth
def debug_jwt():
    """
    Debug endpoint to test JWT token generation and decoding
    """
    import json

    jwt_token = apns._generate_jwt_token()

    if not jwt_token:
        return jsonify({
            "success": False,
            "error": "Failed to generate JWT token"
        }), 500

    try:
        # Decode without verification to inspect the token
        decoded_header = pyjwt.get_unverified_header(jwt_token)
        decoded_payload = pyjwt.decode(jwt_token, options={"verify_signature": False})

        return jsonify({
            "success": True,
            "jwt_token": jwt_token,
            "jwt_length": len(jwt_token),
            "header": decoded_header,
            "payload": decoded_payload,
            "issued_at": decoded_payload.get("iat"),
            "issuer": decoded_payload.get("iss"),
            "key_id_in_header": decoded_header.get("kid"),
            "algorithm": decoded_header.get("alg"),
            "validation": {
                "has_iss": "iss" in decoded_payload,
                "has_iat": "iat" in decoded_payload,
                "has_kid": "kid" in decoded_header,
                "alg_is_ES256": decoded_header.get("alg") == "ES256",
                "kid_matches_config": decoded_header.get("kid") == Config.APNS_KEY_ID,
                "iss_matches_config": decoded_payload.get("iss") == Config.APNS_TEAM_ID
            }
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "jwt_token": jwt_token
        }), 500

@app.route('/debug/config', methods=['GET'])
@require_auth
def debug_config():
    jwt_token = apns._generate_jwt_token()

    return jsonify({
        "apns_key_loaded": apns.auth_key is not None,
        "apns_key_length": len(apns.auth_key) if apns.auth_key else 0,
        "key_id": Config.APNS_KEY_ID,
        "key_id_length": len(Config.APNS_KEY_ID),
        "team_id": Config.APNS_TEAM_ID,
        "team_id_length": len(Config.APNS_TEAM_ID),
        "bundle_id": Config.APNS_TOPIC,
        "environment": "sandbox" if Config.APNS_USE_SANDBOX else "production",
        "endpoint": apns.endpoint,
        "jwt_token_generated": jwt_token is not None,
        "jwt_token_preview": jwt_token[:50] + "..." if jwt_token else None,
        "auth_key_starts_with": apns.auth_key[:50] if apns.auth_key else None
    }), 200


@app.route('/auth/login', methods=['POST'])
def login():
    payload = request.get_json()
    passphrase = payload.get('passphrase')

    if not passphrase or passphrase == '':
        return jsonify({
            'status': False,
            'message': 'Passphrase is empty'
        }), 400

    if passphrase != Config.AUTH_PASSPHRASE:
        return jsonify({
            'status': False,
            'message': 'Wrong Passphrase'
        }), 401

    current_time = int(time.time())
    token_payload = {
        'key': Config.ENCRYPT_KEY,
        'time': current_time,
        'exp': current_time + Config.AUTH_TOKEN_EXPIRY
    }

    token = pyjwt.encode(
        token_payload,
        Config.AUTH_SECRET_KEY,
        algorithm="HS256"
    )

    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({
        'status': True,
        'token': token,
        'expires_in': Config.AUTH_TOKEN_EXPIRY
    }), 200
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    is_configured = apns.auth_key is not None

    return jsonify({
        "status": "healthy" if is_configured else "misconfigured",
        "service": "iOS Push Notification Server",
        "timestamp": datetime.now().isoformat(),
        "apns_configured": is_configured,
        "environment": "sandbox" if Config.APNS_USE_SANDBOX else "production",
        "bundle_id": Config.APNS_TOPIC
    }), 200 if is_configured else 503

@app.route('/send', methods=['POST'])
@require_auth
def send_notification():
    try:
        payload = request.get_json()

        if not payload:
            return jsonify({
                "success": False,
                "error": "No JSON payload provided"
            }), 400

        # Validate required fields
        required_fields = ['device_token', 'title', 'message']
        missing_fields = [field for field in required_fields if field not in payload]

        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields
            }), 400

        device_token = payload['device_token']

        # Validate device token
        is_valid, result = apns.validate_token(device_token)
        if not is_valid:
            return jsonify({
                "success": False,
                "error": "Invalid device token",
                "details": result
            }), 400

        # Use cleaned token
        device_token = result

        # Extract fields
        title = payload['title']
        message = payload['message']
        badge = payload.get('badge')
        sound = payload.get('sound', 'default')
        category = payload.get('category')
        thread_id = payload.get('thread_id')
        data = payload.get('data')
        priority = payload.get('priority', 'high')
        collapse_id = payload.get('collapse_id')
        expiration = payload.get('expiration')

        # Send notification
        result = apns.send_notification(
            device_token=device_token,
            title=title,
            message=message,
            badge=badge,
            sound=sound,
            category=category,
            thread_id=thread_id,
            data=data,
            priority=priority,
            collapse_id=collapse_id,
            expiration=expiration
        )

        status_code = 200 if result['success'] else 400
        db.log_notification(device_token, title, message, success=result['success'],apns_id=result['apns_id'])
        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Error in send_notification: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/send/batch', methods=['POST'])
@require_auth
def send_batch_notifications():
    try:
        payload = request.get_json()

        if not payload:
            return jsonify({
                "success": False,
                "error": "No JSON payload provided"
            }), 400

        notifications = payload.get('notifications', [])

        if not notifications:
            return jsonify({
                "success": False,
                "error": "No notifications provided",
                "hint": "Include a 'notifications' array in your request"
            }), 400

        if not isinstance(notifications, list):
            return jsonify({
                "success": False,
                "error": "Notifications must be an array"
            }), 400

        results = []

        for idx, notification in enumerate(notifications):
            # Validate required fields
            device_token = notification.get('device_token')
            title = notification.get('title')
            message = notification.get('message')

            if not all([device_token, title, message]):
                results.append({
                    "success": False,
                    "index": idx,
                    "device_token": device_token[:8] + "..." if device_token else "missing",
                    "error": "Missing required fields (device_token, title, or message)"
                })
                continue

            # Validate token
            is_valid, token_result = apns.validate_token(device_token)
            if not is_valid:
                results.append({
                    "success": False,
                    "index": idx,
                    "device_token": device_token[:8] + "...",
                    "error": "Invalid device token",
                    "details": token_result
                })
                continue

            device_token = token_result

            # Send notification
            result = apns.send_notification(
                device_token=device_token,
                title=title,
                message=message,
                badge=notification.get('badge'),
                sound=notification.get('sound', 'default'),
                category=notification.get('category'),
                thread_id=notification.get('thread_id'),
                data=notification.get('data'),
                priority=notification.get('priority', 'high'),
                collapse_id=notification.get('collapse_id'),
                expiration=notification.get('expiration')
            )

            result['index'] = idx
            results.append(result)

        success_count = sum(1 for r in results if r.get('success'))
        failed_count = len(results) - success_count

        return jsonify({
            "batch_complete": True,
            "total": len(results),
            "success_count": success_count,
            "failed_count": failed_count,
            "results": results
        }), 200

    except Exception as e:
        logger.error(f"Error in send_batch_notifications: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/validate/token', methods=['POST'])
def validate_token():
    """
    Validate an iOS device token format

    Expected JSON payload:
    {
        "device_token": "token_to_validate"
    }
    """
    try:
        payload = request.get_json()

        if not payload or 'device_token' not in payload:
            return jsonify({
                "valid": False,
                "error": "No device_token provided"
            }), 400

        device_token = payload['device_token']
        is_valid, result = apns.validate_token(device_token)

        if is_valid:
            return jsonify({
                "valid": True,
                "cleaned_token": result,
                "length": len(result)
            }), 200
        else:
            return jsonify({
                "valid": False,
                "error": result
            }), 200

    except Exception as e:
        return jsonify({
            "valid": False,
            "error": str(e)
        }), 500

@app.route('/upload/key', methods=['POST'])
def upload_key():
    try:
        # Expect multipart/form-data
        # Fields: key_id, team_id, bundle_id, environment (optional)
        form = request.form or {}

        key_id = _sanitize_token(form.get("key_id"))
        team_id = _sanitize_token(form.get("team_id"))
        bundle_id = _sanitize_token(form.get("bundle_id"))
        environment = _sanitize_token(form.get("environment") or "sandbox").lower()

        required_fields = ["key_id", "team_id", "bundle_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]

        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields
            }), 400

        # Validate formats (optional but recommended)
        if not _is_valid_key_id(key_id):
            return jsonify({"success": False, "error": "Invalid key_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_team_id(team_id):
            return jsonify({"success": False, "error": "Invalid team_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_bundle_id(bundle_id):
            return jsonify({"success": False, "error": "Invalid bundle_id format"}), 400

        if environment not in ALLOWED_ENVIRONMENTS:
            return jsonify({
                "success": False,
                "error": f"Invalid environment. Allowed: {', '.join(sorted(ALLOWED_ENVIRONMENTS))}"
            }), 400

        # File handling
        file = request.files.get("file")
        if not file or file.filename == "":
            return jsonify({"success": False, "error": "File not found"}), 400

        # Validate extension
        original_name = (file.filename or "").lower()
        if not original_name.endswith(".p8"):
            return jsonify({"success": False, "error": "Invalid file type. Only .p8 is allowed"}), 400

        # Choose upload directory (configure this in your app config)
        upload_dir = app.config.get("APNS_KEYS_DIR", "storage/apns_keys")
        _ensure_upload_dir(upload_dir)

        # Save with deterministic safe name (don’t trust client filename)
        p8_filename = _safe_p8_filename(key_id)
        p8_path = os.path.join(upload_dir, p8_filename)

        # Basic safety: do not overwrite accidentally
        if os.path.exists(p8_path):
            return jsonify({"success": False, "error": "A key with the same generated filename already exists"}), 409

        file.save(p8_path)

        # Persist in DB
        ok = apns.save_apns_config(
            key_id=key_id,
            team_id=team_id,
            bundle_id=bundle_id,
            p8_filename=p8_filename,
            environment=environment
        )

        if not ok:
            # Roll back file if DB save failed
            try:
                if os.path.exists(p8_path):
                    os.remove(p8_path)
            except Exception:
                pass

            return jsonify({
                "success": False,
                "error": "Failed to save APNs configuration"
            }), 500

        return jsonify({
            "success": True,
            "message": "APNs key uploaded and configuration saved",
            "data": {
                "key_id": key_id,
                "team_id": team_id,
                "bundle_id": bundle_id,
                "environment": environment,
                "p8_filename": p8_filename
            }
        }), 201

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "available_endpoints": [
            "POST /auth/login - Get authentication token",
            "GET /auth/verify - Verify token validity",
            "GET /health - Health check (no auth required)",
            "POST /send - Send single notification (requires auth)",
            "POST /send/batch - Send batch notifications (requires auth)",
            "POST /validate/token - Validate device token (no auth required)"
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

# ==================== Main ====================
if __name__ == '__main__':
    print("=" * 60)
    print("iOS Push Notification Server Starting...")
    print("=" * 60)
    print(f"Environment: {'SANDBOX' if Config.APNS_USE_SANDBOX else 'PRODUCTION'}")
    print(f"Bundle ID: {Config.APNS_TOPIC}")
    print(f"APNs Configured: {apns.auth_key is not None}")
    print(f"Auth Token Expiry: {Config.AUTH_TOKEN_EXPIRY // 3600} hours")
    print(f"Port: {Config.PORT}")
    print("=" * 60)

    if not apns.auth_key:
        print("⚠️  WARNING: APNs authentication key not loaded!")
        print(f"   Please ensure {Config.APNS_AUTH_KEY_PATH} exists")
        print("=" * 60)

    if Config.AUTH_PASSPHRASE == "your_secure_passphrase_here_change_this":
        print("⚠️  WARNING: Default passphrase detected!")
        print("   Please change AUTH_PASSPHRASE in Config for security!")
        print("=" * 60)

    print("\n🔐 Authentication enabled!")
    print("   Use POST /auth/login with your passphrase to get a token")
    print("=" * 60)

    app.run(
        host='0.0.0.0',
        port=Config.PORT,
        debug=Config.DEBUG
    )