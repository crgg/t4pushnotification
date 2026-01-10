"""
iOS Push Notification Server (APNs) - Production Ready
Handles Apple Push Notification service exclusively

Requirements:
pip install flask PyJWT cryptography httpx[http2] gunicorn python-dotenv redis flask-limiter
"""

from flask import Flask, request, jsonify
import jwt as pyjwt
import time
from datetime import datetime
from functools import wraps
import logging
import re
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import Config
from app.db import DatabaseHandler
from app.apns_client import APNsHandler
from app.company import CompanyHandler
from app.project import ProjectHandler

# ==================== Application Setup ====================
app = Flask(__name__)

# Security Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# ==================== Logging Configuration ====================
def setup_logging():
    """Configure production-grade logging with rotation"""
    log_dir = os.getenv('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Main application log
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'apns_server.log'),
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Error log
    error_handler = RotatingFileHandler(
        os.path.join(log_dir, 'apns_errors.log'),
        maxBytes=10485760,
        backupCount=10
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)

    # Console handler for container logs
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO if not Config.DEBUG else logging.DEBUG)
    console_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    root_logger.addHandler(console_handler)

    # Silence noisy libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

setup_logging()
logger = logging.getLogger(__name__)

# ==================== Rate Limiting ====================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=os.getenv('REDIS_URL', 'memory://'),
    default_limits=["1000 per hour", "100 per minute"],
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window"
)

# ==================== Configuration ====================
app.config.setdefault("APNS_KEYS_DIR", os.getenv("APNS_KEYS_DIR", "storage/apns_keys"))
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max file size
app.config['JSON_SORT_KEYS'] = False

ALLOWED_ENVIRONMENTS = {"sandbox", "production"}
MAX_DEVICE_TOKEN_LENGTH = 200
MAX_TITLE_LENGTH = 500
MAX_MESSAGE_LENGTH = 4096

# ==================== Input Validation Helpers ====================
def _sanitize_token(value: str) -> str:
    """Sanitize and validate input strings"""
    if not isinstance(value, str):
        return ""
    return value.strip()[:1000]  # Prevent excessively long inputs

def _is_valid_key_id(key_id: str) -> bool:
    """Validate Apple APNs Key ID format"""
    return bool(re.fullmatch(r"[A-Z0-9]{10}", key_id or ""))

def _is_valid_team_id(team_id: str) -> bool:
    """Validate Apple Team ID format"""
    return bool(re.fullmatch(r"[A-Z0-9]{10}", team_id or ""))

def _is_valid_bundle_id(bundle_id: str) -> bool:
    """Validate iOS Bundle ID format"""
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", bundle_id or ""))

def _is_valid_company_id(company_id: str) -> bool:
    """Validate company ID is numeric"""
    return bool(re.fullmatch(r"[0-9]+", company_id or ""))

def _is_valid_email(email: str) -> bool:
    """Basic email validation"""
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email or ""))

def _ensure_upload_dir(upload_dir: str) -> None:
    """Safely create upload directory with secure permissions"""
    os.makedirs(upload_dir, mode=0o700, exist_ok=True)

def _safe_p8_basename(key_id: str) -> str:
    """Generate safe filename for P8 key"""
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"AuthKey_{key_id}_{ts}.p8"

# ==================== Encryption Helpers ====================
def get_enc_key_and_version():
    """
    Retrieve encryption key and version from environment
    Uses: APNS_ENCRYPTION_KEY_B64 (base64 of 32 bytes)
          APNS_KEY_VERSION (integer, default 1)
    """
    key_b64 = os.getenv("APNS_ENCRYPTION_KEY_B64")
    if not key_b64:
        logger.critical("APNS_ENCRYPTION_KEY_B64 environment variable is not set")
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 is not set")

    try:
        key = base64.b64decode(key_b64)
    except Exception as e:
        logger.critical(f"Failed to decode APNS_ENCRYPTION_KEY_B64: {e}")
        raise RuntimeError("Invalid APNS_ENCRYPTION_KEY_B64 encoding")

    if len(key) != 32:
        logger.critical(f"APNS_ENCRYPTION_KEY_B64 decoded to {len(key)} bytes, expected 32")
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 must decode to 32 bytes (AES-256)")

    version = int(os.getenv("APNS_KEY_VERSION", "1"))
    return key, version

def encrypt_bytes_aesgcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt bytes using AES-GCM"""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def sha256_hex(data: bytes) -> str:
    """Calculate SHA-256 hash and return as hex string"""
    return hashlib.sha256(data).hexdigest()

# ==================== Authentication Decorator ====================
def require_auth(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(f"Missing or invalid Authorization header from {get_remote_address()}")
            return jsonify({"status": False, "message": "Authentication required"}), 401

        token = auth_header.split("Bearer ", 1)[1].strip()

        if not token:
            return jsonify({"status": False, "message": "Authentication required"}), 401

        try:
            pyjwt.decode(token, Config.AUTH_SECRET_KEY, algorithms=["HS256"])
        except pyjwt.ExpiredSignatureError:
            logger.warning(f"Expired token attempt from {get_remote_address()}")
            return jsonify({"status": False, "message": "Auth token expired"}), 401
        except pyjwt.InvalidTokenError as e:
            logger.warning(f"Invalid token attempt from {get_remote_address()}: {str(e)}")
            return jsonify({"status": False, "message": "Invalid auth token"}), 401
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}", exc_info=True)
            return jsonify({"status": False, "message": "Authentication failed"}), 401

        return f(*args, **kwargs)
    return decorated_function

# ==================== Error Handlers ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"success": False, "error": "Method not allowed"}), 405

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"success": False, "error": "File too large. Maximum size is 1MB"}), 413

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"success": False, "error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return jsonify({"success": False, "error": "An unexpected error occurred"}), 500

# ==================== Initialize Handlers ====================
apns = APNsHandler()
db = DatabaseHandler()
company = CompanyHandler()
project = ProjectHandler()

# Load active configuration at startup
if apns.has_active_config():
    try:
        apns.reload_from_active_config()
        logger.info("Active APNs configuration loaded from database at startup")
    except Exception as e:
        logger.error(
            "✗ Active APNs config exists but failed to load. "
            "Service is misconfigured and will not be able to send notifications.",
            exc_info=True
        )
else:
    logger.warning(
        "No active APNs configuration found. "
        "Upload a .p8 key via /upload/key to enable notifications."
    )

# ==================== API Routes ====================
@app.route("/", methods=["GET"])
def index():
    """Root endpoint with API information"""
    return jsonify({
        "service": "iOS Push Notification Server",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "auth": "/auth/login",
            "health": "/health",
            "send": "/send",
            "keys": {
                "list": "/keys/list",
                "upload": "/upload/key",
                "activate": "/keys/activate",
                "assign": "/keys/assign"
            },
            "company": "/company/new",
            "project": {
                "new": "/project/new",
                "assign": "/project/assign"
            }
        }
    }), 200

@app.route("/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """Authenticate and receive JWT token"""
    try:
        payload = request.get_json() or {}
        passphrase = payload.get("passphrase")

        if not passphrase:
            logger.warning(f"Empty passphrase attempt from {get_remote_address()}")
            return jsonify({"status": False, "message": "Passphrase is required"}), 400

        if passphrase != Config.AUTH_PASSPHRASE:
            logger.warning(f"Failed login attempt from {get_remote_address()}")
            return jsonify({"status": False, "message": "Invalid passphrase"}), 401

        current_time = int(time.time())
        token_payload = {
            "key": Config.ENCRYPT_KEY,
            "time": current_time,
            "exp": current_time + Config.AUTH_TOKEN_EXPIRY,
        }

        token = pyjwt.encode(token_payload, Config.AUTH_SECRET_KEY, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        logger.info(f"Successful login from {get_remote_address()}")
        return jsonify({
            "status": True,
            "token": token,
            "expires_in": Config.AUTH_TOKEN_EXPIRY
        }), 200

    except Exception as e:
        logger.error(f"Error in login: {e}", exc_info=True)
        return jsonify({"status": False, "message": "Authentication failed"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for load balancers"""
    is_configured = apns.auth_key is not None
    env = "sandbox" if apns.endpoint and apns.endpoint.endswith("sandbox.push.apple.com") else "production"

    return jsonify({
        "status": "healthy" if is_configured else "misconfigured",
        "service": "iOS Push Notification Server",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "apns_configured": is_configured,
        "environment": env if is_configured else None,
        "bundle_id": apns.bundle_id if is_configured else None,
    }), (200 if is_configured else 503)

@app.route("/send", methods=["POST"])
@require_auth
@limiter.limit("100 per minute")
def send_notification():
    """Send push notification to device"""
    try:
        payload = request.get_json(silent=True) or request.form.to_dict() or {}
        required_fields = ["device_token", "title", "message"]
        missing_fields = [f for f in required_fields if not payload.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
                "hint": "Send JSON with Content-Type: application/json or use form-data fields.",
            }), 400

        device_token = payload["device_token"]
        title = payload["title"]
        message = payload["message"]

        # Validate field lengths
        if len(device_token) > MAX_DEVICE_TOKEN_LENGTH:
            return jsonify({"success": False, "error": "Device token too long"}), 400
        if len(title) > MAX_TITLE_LENGTH:
            return jsonify({"success": False, "error": f"Title exceeds {MAX_TITLE_LENGTH} characters"}), 400
        if len(message) > MAX_MESSAGE_LENGTH:
            return jsonify({"success": False, "error": f"Message exceeds {MAX_MESSAGE_LENGTH} characters"}), 400

        # Validate device token
        is_valid, result = apns.validate_token(device_token)
        if not is_valid:
            return jsonify({"success": False, "error": "Invalid device token", "details": result}), 400

        device_token = result

        # Send notification
        result = apns.send_notification(
            device_token=device_token,
            title=title,
            message=message,
            badge=payload.get("badge"),
            sound=payload.get("sound", "default"),
            category=payload.get("category"),
            thread_id=payload.get("thread_id"),
            data=payload.get("data"),
            priority=payload.get("priority", "high"),
            collapse_id=payload.get("collapse_id"),
            expiration=payload.get("expiration"),
            pushtype=payload.get("pushtype")
        )

        status_code = 200 if result.get("success") else 400

        # Log notification
        db.log_notification(
            device_token,
            title,
            message,
            success=result.get("success"),
            apns_id=result.get("apns_id"),
        )

        if result.get("success"):
            logger.info(f"Notification sent successfully. APNs ID: {result.get('apns_id')}")
        else:
            logger.warning(f"Notification failed: {result.get('error')}")

        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Error in send_notification: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to send notification"}), 500

@app.route("/keys/list", methods=["GET"])
@require_auth
def list_keys():
    """List all registered APNs keys"""
    try:
        rows = apns.list_apn_keys()
        items = []

        for r in rows:
            _id, key_id, team_id, bundle_id,p8_filename, company_id, environment, is_active, created_at = r
            items.append({
                "id": _id,
                "key_id": key_id,
                "team_id": team_id,
                "bundle_id": bundle_id,
                "p8_filename" : p8_filename,
                "company_id": company_id,
                "environment": environment,
                "is_active": bool(is_active),
                "created_at": created_at.isoformat() if created_at else None,
            })

        return jsonify({"success": True, "data": items}), 200

    except Exception as e:
        logger.error(f"Error listing keys: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to retrieve keys"}), 500

@app.route("/keys/activate", methods=["POST"])
@require_auth
def activate_key():
    """Activate a specific APNs configuration"""
    try:
        payload = request.get_json() or {}
        bundle_id = _sanitize_token(payload.get("bundle_id", ""))
        environment = _sanitize_token(payload.get("environment", "")).lower() or None

        if not bundle_id:
            return jsonify({"success": False, "error": "bundle_id is required"}), 400

        if environment and environment not in ALLOWED_ENVIRONMENTS:
            return jsonify({"success": False, "error": "environment must be 'sandbox' or 'production'"}), 400

        ok = apns.activate_apns_config_by_bundle(bundle_id=bundle_id, environment=environment)
        if not ok:
            return jsonify({"success": False, "error": "No configuration found for specified bundle_id/environment"}), 404

        apns.reload_from_active_config()
        logger.info(f"Activated APNs config: {bundle_id} ({environment})")

        return jsonify({
            "success": True,
            "message": "Active APNs configuration updated",
            "active": {"bundle_id": bundle_id, "environment": environment}
        }), 200

    except Exception as e:
        logger.error(f"Error activating key: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to activate configuration"}), 500

@app.route("/upload/key", methods=["POST"])
@require_auth
@limiter.limit("10 per hour")
def upload_key():
    """Upload and encrypt APNs .p8 key"""
    try:
        form = request.form or {}

        # Extract and sanitize fields
        key_id = _sanitize_token(form.get("key_id", ""))
        team_id = _sanitize_token(form.get("team_id", ""))
        bundle_id = _sanitize_token(form.get("bundle_id", ""))
        company_id = _sanitize_token(form.get("company_id", ""))
        environment = _sanitize_token(form.get("environment", "sandbox")).lower()

        # Validate required fields
        required_fields = ["key_id", "team_id", "bundle_id", "company_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }), 400

        # Validate formats
        if not _is_valid_key_id(key_id):
            return jsonify({"success": False, "error": "Invalid key_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_team_id(team_id):
            return jsonify({"success": False, "error": "Invalid team_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_company_id(company_id):
            return jsonify({"success": False, "error": "Invalid company_id format (must be numeric)"}), 400
        if not _is_valid_bundle_id(bundle_id):
            return jsonify({"success": False, "error": "Invalid bundle_id format"}), 400
        if environment not in ALLOWED_ENVIRONMENTS:
            return jsonify({"success": False, "error": "Invalid environment (sandbox|production)"}), 400

        # Validate file
        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"success": False, "error": "File not provided"}), 400

        if not file.filename.lower().endswith(".p8"):
            return jsonify({"success": False, "error": "Invalid file type. Only .p8 files allowed"}), 400

        raw = file.read()
        if not raw:
            return jsonify({"success": False, "error": "Empty file"}), 400

        if len(raw) > 100000:  # ~100KB max for P8 key
            return jsonify({"success": False, "error": "File too large for P8 key"}), 400

        # Encrypt the key
        upload_dir = app.config["APNS_KEYS_DIR"]
        _ensure_upload_dir(upload_dir)

        enc_key, key_version = get_enc_key_and_version()
        nonce, ciphertext = encrypt_bytes_aesgcm(raw, enc_key)

        p8_basename = _safe_p8_basename(key_id)
        enc_filename = f"{p8_basename}.enc"
        raw_hash = sha256_hex(raw)

        # Save to database
        ok = apns.save_apns_config(
            key_id=key_id,
            team_id=team_id,
            bundle_id=bundle_id,
            p8_filename=p8_basename,
            environment=environment,
            enc_alg="AES-256-GCM",
            enc_filename=enc_filename,
            enc_nonce=nonce,
            key_version=key_version,
            file_sha256=raw_hash,
            enc_blob=ciphertext,
            company_id=company_id,
        )

        if not ok:
            logger.error("Failed to save APNs configuration to database")
            return jsonify({"success": False, "error": "Failed to save APNs configuration"}), 500

        apns.reload_from_active_config()
        logger.info(f"APNs key uploaded: {key_id} for bundle {bundle_id}")

        return jsonify({
            "success": True,
            "message": "APNs key uploaded, encrypted, and configuration saved",
            "data": {
                "key_id": key_id,
                "team_id": team_id,
                "bundle_id": bundle_id,
                "environment": environment,
                "p8_filename": p8_basename,
                "enc_filename": enc_filename,
                "key_version": key_version,
            },
        }), 201

    except Exception as e:
        logger.error(f"Error uploading key: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to upload key"}), 500

@app.route("/company/new", methods=["POST"])
@require_auth
def company_new():
    """Create a new company record"""
    try:
        form = request.form or {}
        name = _sanitize_token(form.get("name", ""))
        address = _sanitize_token(form.get("address", ""))
        email = _sanitize_token(form.get("email", ""))
        phone = _sanitize_token(form.get("phone", ""))
        url = _sanitize_token(form.get("url", ""))

        # Validate required fields
        required_fields = ["name", "address"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }), 400

        # Validate email if provided
        if email and not _is_valid_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400

        ok = company.save_company(name, address, phone, email, url)
        if not ok:
            logger.error(f"Failed to save company: {name}")
            return jsonify({"success": False, "error": "Failed to save company"}), 500

        logger.info(f"New company created: {name}")
        return jsonify({
            "success": True,
            "message": "Company created successfully",
            "data": {
                "name": name,
                "address": address,
                "email": email,
                "phone": phone,
                "url": url
            },
        }), 201

    except Exception as e:
        logger.error(f"Error creating company: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to create company"}), 500


@app.route('/companies/list',methods=["GET"])
@require_auth
def get_companies():
    try:
        rows = company.company_list()
        items = []

        for r in rows:
            _id, name, address, phone, email, url, created_at, updated_at = r
            items.append({
                "id": _id,
                "name": name,
                "address": address,
                "phone": phone,
                "email": email,
                "url": url,
                "created_at": created_at.isoformat() if created_at else None,
                "updated_at": updated_at.isoformat() if updated_at else None,
            })

        return jsonify({"success": True, "data": items}), 200

    except Exception as e:
        logger.error(f"Error listing keys: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to retrieve keys"}), 500

@app.route('/logs',methods=["GET"])
@require_auth
def get_logs():
    try:
        rows = db.get_stats()
        items = []

        for r in rows:
            _id, device_token,title,message,badge,sound, category,thread_id,custom_data,priority,success,error_code,error_message,apns_id,status_code,ip_address,created_at = r
            items.append({
                "id": _id,
                "device_token": device_token,
                "title": title,
                "message": message,
                "badge": badge,
                "sound": sound,
                "category": category,
                "thread_id": thread_id,
                "custom_data": custom_data,
                "priority": priority,
                "success": success,
                "error_code": error_code,
                "error_message": error_message,
                "apns_id": apns_id,
                "status_code": status_code,
                "ip_address": ip_address,
                "created_at": created_at
            })
        return jsonify({"success": True, "data": items}), 200
    except Exception as e:
        logger.error(f"Error listing logs: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to retrieve logs"}), 500


@app.route("/keys/assign", methods=["POST"])
@require_auth
def assign_key():
    """Assign a key to a company"""
    try:
        form = request.form or {}
        company_id = form.get("company_id", "")
        key_id = form.get("key_id", "")

        required_fields = ["key_id", "company_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }), 400

        ok = company.assign_key(company_id, key_id)
        if not ok:
            logger.error(f"Failed to assign key {key_id} to company {company_id}")
            return jsonify({"success": False, "error": "Failed to assign key to company"}), 500

        logger.info(f"Key {key_id} assigned to company {company_id}")
        return jsonify({
            "success": True,
            "message": "Key assigned to company successfully"
        }), 200

    except Exception as e:
        logger.error(f"Error assigning key: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to assign key"}), 500

@app.route("/project/new", methods=["POST"])
@require_auth
def project_new():
    """Create a new project"""
    try:
        form = request.form or {}
        name = _sanitize_token(form.get("name", ""))
        url = _sanitize_token(form.get("url", ""))

        required_fields = ["name", "url"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }), 400

        ok = project.save_project(name, url)
        if not ok:
            logger.error(f"Failed to create project: {name}")
            return jsonify({"success": False, "error": "Failed to create project"}), 500

        logger.info(f"New project created: {name}")
        return jsonify({
            "success": True,
            "message": "Project created successfully"
        }), 201

    except Exception as e:
        logger.error(f"Error creating project: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to create project"}), 500

@app.route("/project/assign", methods=["POST"])
@require_auth
def project_assign():
    """Assign a project to a key"""
    try:
        form = request.form or {}
        key_id = form.get("key_id", "")
        project_id = form.get("project_id", "")

        required_fields = ["key_id", "project_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }), 400

        ok = apns.assign_project(project_id, key_id)
        if not ok:
            logger.error(f"Failed to assign project {project_id} to key {key_id}")
            return jsonify({"success": False, "error": "Failed to assign project to key"}), 500

        logger.info(f"Project {project_id} assigned to key {key_id}")
        return jsonify({
            "success": True,
            "message": "Project assigned to key successfully"
        }), 200

    except Exception as e:
        logger.error(f"Error assigning project: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to assign project"}), 500

# ==================== Main ====================
if __name__ == "__main__":
    # Development mode only
    logger.warning("Running in development mode. Use Gunicorn for production!")
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)