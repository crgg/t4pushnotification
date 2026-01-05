"""
iOS Push Notification Server (APNs)
Handles Apple Push Notification service exclusively

Requirements:
pip install flask PyJWT cryptography httpx[http2]
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

from app.config import Config
from app.db import DatabaseHandler
from app.apns_client import APNsHandler
from app.company import CompanyHandler
from app.project import ProjectHandler
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Directory to store encrypted APNs keys (ciphertext only)
app.config.setdefault("APNS_KEYS_DIR", "storage/apns_keys")

ALLOWED_ENVIRONMENTS = {"sandbox", "production"}


# ==================== Helpers ====================
def _sanitize_token(value: str) -> str:
    return (value or "").strip()


def _is_valid_key_id(key_id: str) -> bool:
    return bool(re.fullmatch(r"[A-Z0-9]{10}", key_id or ""))


def _is_valid_team_id(team_id: str) -> bool:
    return bool(re.fullmatch(r"[A-Z0-9]{10}", team_id or ""))


def _is_valid_bundle_id(bundle_id: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", bundle_id or ""))

def _is_valid_company_id(company_id: str) -> bool:
    return bool(re.fullmatch(r"[0-9]",company_id or "") )

def _ensure_upload_dir(upload_dir: str) -> None:
    os.makedirs(upload_dir, exist_ok=True)


def _safe_p8_basename(key_id: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"AuthKey_{key_id}_{ts}.p8"


def get_enc_key_and_version():
    """
    Uses:
      APNS_ENCRYPTION_KEY_B64 (base64 of 32 bytes)
      APNS_KEY_VERSION (integer, default 1)
    """
    key_b64 = os.getenv("APNS_ENCRYPTION_KEY_B64")
    if not key_b64:
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 is not set")

    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise RuntimeError("APNS_ENCRYPTION_KEY_B64 must decode to 32 bytes (AES-256)")

    version = int(os.getenv("APNS_KEY_VERSION", "1"))
    return key, version


def encrypt_bytes_aesgcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext includes tag
    return nonce, ciphertext


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ==================== Authentication Decorator ====================
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split("Bearer ", 1)[1].strip() if auth_header.startswith("Bearer ") else None

        if not token:
            return jsonify({"status": False, "message": "Authentication required"}), 401

        try:
            pyjwt.decode(token, Config.AUTH_SECRET_KEY, algorithms=["HS256"])
        except pyjwt.ExpiredSignatureError:
            return jsonify({"status": False, "message": "Auth Token expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"status": False, "message": "Invalid Auth token"}), 401

        return f(*args, **kwargs)

    return decorated_function


# ==================== APNs Handler / DB ====================
apns = APNsHandler()
db = DatabaseHandler()
company = CompanyHandler()
project = ProjectHandler()

if apns.has_active_config():
    try:
        apns.reload_from_active_config()
        logger.info("✓ Active APNs configuration loaded from DB at startup")
    except Exception as e:
        logger.error(
            "✗ Active APNs config exists but failed to load. "
            "Service is misconfigured and will not be able to send notifications.",
            exc_info=e
        )
else:
    logger.info(
        "No active APNs configuration found (first boot). "
        "Upload a .p8 key via /upload/key to enable notifications."
    )

# ==================== API Routes ====================
@app.route("/auth/login", methods=["POST"])
def login():
    payload = request.get_json() or {}
    passphrase = payload.get("passphrase")

    if not passphrase:
        return jsonify({"status": False, "message": "Passphrase is empty"}), 400

    if passphrase != Config.AUTH_PASSPHRASE:
        return jsonify({"status": False, "message": "Wrong Passphrase"}), 401

    current_time = int(time.time())
    token_payload = {
        "key": Config.ENCRYPT_KEY,
        "time": current_time,
        "exp": current_time + Config.AUTH_TOKEN_EXPIRY,
    }

    token = pyjwt.encode(token_payload, Config.AUTH_SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return jsonify({"status": True, "token": token, "expires_in": Config.AUTH_TOKEN_EXPIRY}), 200


@app.route("/health", methods=["GET"])
def health_check():
    is_configured = apns.auth_key is not None
    return jsonify(
        {
            "status": "healthy" if is_configured else "misconfigured",
            "service": "iOS Push Notification Server",
            "timestamp": datetime.now().isoformat(),
            "apns_configured": is_configured,
            "environment": "sandbox" if apns.endpoint.endswith("sandbox.push.apple.com") else "production",
            "bundle_id": apns.bundle_id,
        }
    ), (200 if is_configured else 503)


@app.route("/send", methods=["POST"])
@require_auth
def send_notification():
    try:
        payload = request.get_json() or {}
        required_fields = ["device_token", "title", "message"]
        missing_fields = [f for f in required_fields if f not in payload]
        if missing_fields:
            return jsonify(
                {
                    "success": False,
                    "error": f"Missing required fields: {', '.join(missing_fields)}",
                    "required_fields": required_fields,
                }
            ), 400

        device_token = payload["device_token"]
        is_valid, result = apns.validate_token(device_token)
        if not is_valid:
            return jsonify({"success": False, "error": "Invalid device token", "details": result}), 400

        device_token = result

        result = apns.send_notification(
            device_token=device_token,
            title=payload["title"],
            message=payload["message"],
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
        db.log_notification(
            device_token,
            payload["title"],
            payload["message"],
            success=result.get("success"),
            apns_id=result.get("apns_id"),
        )
        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Error in send_notification: {e}")
        return jsonify({"success": False, "error": "Internal server error", "details": str(e)}), 500


@app.route("/keys/list",methods=["GET"])
@require_auth
def list_keys():
    try:
        rows = apns.list_apn_keys()

        items = []
        for r in rows:
            (
                _id,
                key_id,
                team_id,
                bundle_id,
                company_id,
                environment,
                is_active,
                created_at,
            ) = r

            items.append({
                "id": _id,
                "key_id": key_id,
                "team_id": team_id,
                "bundle_id": bundle_id,
                "company_id": company_id,
                "environment": environment,
                "is_active": bool(is_active),
                "created_at": created_at.isoformat() if created_at else None,
            })

        return jsonify({"success": True, "data": items}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/keys/activate", methods=["POST"])
@require_auth
def activate_key():
    try:
        payload = request.get_json() or {}
        bundle_id = (payload.get("bundle_id") or "").strip()
        environment = (payload.get("environment") or "").strip().lower() or None

        if not bundle_id:
            return jsonify({"success": False, "error": "bundle_id is required"}), 400

        if environment and environment not in {"sandbox", "production"}:
            return jsonify({"success": False, "error": "environment must be sandbox or production"}), 400

        ok = apns.activate_apns_config_by_bundle(bundle_id=bundle_id, environment=environment)
        if not ok:
            return jsonify({"success": False, "error": "No config found for that bundle_id/environment"}), 404

        apns.reload_from_active_config()

        return jsonify({
            "success": True,
            "message": "Active APNs configuration updated",
            "active": {
                "bundle_id": bundle_id,
                "environment": environment
            }
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
@app.route("/upload/key", methods=["POST"])
@require_auth
def upload_key():
    try:
        form = request.form or {}

        key_id = _sanitize_token(form.get("key_id"))
        team_id = _sanitize_token(form.get("team_id"))
        bundle_id = _sanitize_token(form.get("bundle_id"))
        company_id = _sanitize_token(form.get("company_id"))
        environment = _sanitize_token(form.get("environment") or "sandbox").lower()

        required_fields = ["key_id", "team_id", "bundle_id", "company_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify(
                {
                    "success": False,
                    "error": f"Missing required fields: {', '.join(missing_fields)}",
                    "required_fields": required_fields,
                }
            ), 400

        if not _is_valid_key_id(key_id):
            return jsonify({"success": False, "error": "Invalid key_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_team_id(team_id):
            return jsonify({"success": False, "error": "Invalid team_id format (expected 10 chars A-Z0-9)"}), 400
        if not _is_valid_company_id(company_id):
            return jsonify({"success": False, "error": "Invalid company_id format (must be an integer)"}), 400
        if not _is_valid_bundle_id(bundle_id):
            return jsonify({"success": False, "error": "Invalid bundle_id format"}), 400
        if environment not in ALLOWED_ENVIRONMENTS:
            return jsonify({"success": False, "error": "Invalid environment (sandbox|production)"}), 400

        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"success": False, "error": "File not found"}), 400

        if not file.filename.lower().endswith(".p8"):
            return jsonify({"success": False, "error": "Invalid file type. Only .p8 is allowed"}), 400

        raw = file.read()
        if not raw:
            return jsonify({"success": False, "error": "Empty file"}), 400

        upload_dir = app.config["APNS_KEYS_DIR"]
        _ensure_upload_dir(upload_dir)

        enc_key, key_version = get_enc_key_and_version()
        nonce, ciphertext = encrypt_bytes_aesgcm(raw, enc_key)

        p8_basename = _safe_p8_basename(key_id)
        enc_filename = f"{p8_basename}.enc"

        raw_hash = sha256_hex(raw)

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

            return jsonify({"success": False, "error": "Failed to save APNs configuration"}), 500

        apns.reload_from_active_config()

        return jsonify(
            {
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
            }
        ), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/company/new",methods=["POST"])
@require_auth
def company_new():
    try:
        form = request.form or {}
        name = _sanitize_token(form.get("name"))
        address = _sanitize_token(form.get("address"))
        email = _sanitize_token(form.get("email"))
        phone = _sanitize_token(form.get("phone"))
        url = _sanitize_token(form.get('url'))

        required_fields = ["name", "address"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify(
                {
                    "success": False,
                    "error": f"Missing required fields: {', '.join(missing_fields)}",
                    "required_fields": required_fields,
                }
            ), 400

        ok = company.save_company(name, address, phone,email, url)
        if not ok:
            return jsonify({"success": False, "error": "Failed to save new Company"}), 500

        return jsonify(
            {
                "success": True,
                "message": "Company saved",
                "data": {
                    "name" : name,
                    "address" : address,
                    "email": email,
                    "phone": phone,
                    "url": url
                },
            }
        ), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/keys/assign", methods=["POST"])
@require_auth
def assign_key():
    try:
        form = request.form or {}
        company_id = form.get("company_id")
        key_id = form.get("key_id")

        required_fields = ["key_id","company_id"]
        missing_fields = [f for f in required_fields if not form.get(f)]
        if missing_fields:
            return jsonify(
                {
                    "success": False,
                    "error": f"Missing required fields: {', '.join(missing_fields)}",
                    "required_fields": required_fields,
                }
            ), 400

        ok = company.assign_key(company_id, key_id)
        if not ok:
            return jsonify({"success": False, "error": "Failed to assign a company_id to a key"})

        return jsonify({
            "success": True,
            "message" : "Key assigned to a Company"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/project/new", methods=["POST"])
@require_auth
def project_new():
    form = request.form or {}
    name = form.get("name")
    url = form.get("url")

    required_fields = ["name","url"]
    missing_fields = [f for f in required_fields if not form.get(f)]
    if missing_fields:
        return jsonify(
            {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }
        ), 400
    ok = project.save_project(name, url)
    if not ok:
        return jsonify({"success": False, "error": "Failed to create a new project"})

    return jsonify({
        "success" : True,
        "message" : "project saved"
    })

@app.route("/project/assign", methods=["POST"])
@require_auth
def project_assign():
    form = request.form or {}
    key_id = form.get("key_id")
    project_id = form.get("project_id")
    required_fields = ["key_id","project_id"]
    missing_fields = [f for f in required_fields if not form.get(f)]
    if missing_fields:
        return jsonify(
            {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
            }
        ), 400
    ok = apns.assign_project(project_id, key_id)
    if not ok:
        return jsonify({"success": False, "error": "Failed to assign a project_id to a key"})
    return jsonify({
        "success" : True,
        "message" : "Project_id assigned to key"
    })


# ==================== Main ====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)