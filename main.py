"""
iOS Push Notification Server (APNs)
Handles Apple Push Notification service exclusively

Requirements:
pip install flask PyJWT cryptography httpx[http2]
"""

from flask import Flask, request, jsonify
import jwt
import time
import httpx
from datetime import datetime
from pathlib import Path
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================
class Config:
    # APNs Configuration
    APNS_KEY_ID = "Q38C4NR93H"  # 10 character Key ID from Apple Developer Console
    APNS_TEAM_ID = "7T5KXK2RFT"  # 10 character Team ID
    APNS_AUTH_KEY_PATH = "AuthKey_7SFU38488U.p8"  # Path to your .p8 file
    APNS_TOPIC = "t4app.com.t4ever"  # Your iOS app's bundle ID
    APNS_USE_SANDBOX = True  # True for development, False for production

    # Server Configuration
    PORT = 5000
    DEBUG = True

    # Token expiration time (in seconds) - APNs tokens are valid for 1 hour
    JWT_TOKEN_EXPIRY = 3600  # 1 hour

# ==================== APNs Handler ====================
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

    def _generate_jwt_token(self):
        """Generate JWT token for APNs authentication (cached for 1 hour)"""
        if not self.auth_key:
            return None

        # Return cached token if still valid
        current_time = int(time.time())
        #if self.cached_token and current_time < self.token_expiry:
        #    return self.cached_token

        headers = {
            "alg": "ES256",
            "kid": self.key_id
        }

        payload = {
            "iss": self.team_id,
            "iat": current_time
        }

        try:
            token = jwt.encode(
                payload,
                self.auth_key,
                algorithm="ES256",
                headers=headers
            )

            # Cache the token
            self.cached_token = token
            self.token_expiry = current_time + Config.JWT_TOKEN_EXPIRY - 60  # 1 minute buffer

            logger.info("New JWT token generated and cached")
            return token
        except Exception as e:
            logger.error(f"Error generating JWT token: {str(e)}")
            return None

    def send_notification(self, device_token, title, message, badge=None, sound="default",
                          category=None, thread_id=None, data=None, priority="high",
                          collapse_id=None, expiration=None):
        """
        Send push notification to iOS device

        Args:
            device_token: APNs device token
            title: Notification title
            message: Notification body
            badge: Badge count (optional)
            sound: Sound to play (default: "default")
            category: Notification category for actions (optional)
            thread_id: Thread identifier for grouping (optional)
            data: Custom data dictionary (optional)
            priority: "high" (10) or "low" (5)
            collapse_id: Identifier for notification coalescing (optional)
            expiration: Unix timestamp when notification expires (optional)
        """
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

        # Build the alert payload
        alert = {
            "title": title,
            "body": message
        }

        # Build the aps payload
        aps = {
            "alert": alert,
            "sound": sound
        }

        # Add optional aps fields
        if badge is not None:
            aps["badge"] = badge

        if category:
            aps["category"] = category

        if thread_id:
            aps["thread-id"] = thread_id

        # Build the complete payload
        payload = {"aps": aps}

        # Add custom data if provided
        if data and isinstance(data, dict):
            payload.update(data)

        # APNs HTTP/2 endpoint
        url = f"{self.endpoint}/3/device/{device_token}"

        # Build headers
        headers = {
            "authorization": f"bearer {jwt_token}",
            "apns-topic": self.bundle_id,
            "apns-push-type": "alert",
            "apns-priority": "10" if priority == "high" else "5"
        }

        # Add optional headers
        if collapse_id:
            headers["apns-collapse-id"] = collapse_id

        if expiration is not None:
            headers["apns-expiration"] = str(expiration)
        else:
            headers["apns-expiration"] = "0"  # Immediate expiration if not delivered

        try:
            # Use httpx with HTTP/2 support
            with httpx.Client(http2=True, timeout=30.0, verify=True) as client:
                response = client.post(
                    url,
                    headers=headers,
                    json=payload
                )

            #Checkear el response
            #Aqui probablemente viene el error.
            if response.status_code == 200:
                logger.info(f"✓ Notification sent successfully to token: {device_token[:8]}...")
                return {
                    "success": True,
                    "message": "Notification sent successfully",
                    "apns_id": response.headers.get("apns-id"),
                    "device_token": device_token[:8] + "..."  # Partial token for logging
                }
            else:
                # Parse APNs error response
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
        """Get human-readable description of APNs error"""
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

    def validate_token(self, device_token):
        """Validate device token format"""
        # APNs tokens are 64 hexadecimal characters
        if not device_token:
            return False, "Device token is empty"

        # Remove any spaces or angle brackets
        clean_token = device_token.replace(" ", "").replace("<", "").replace(">", "")

        if len(clean_token) != 64:
            return False, f"Invalid token length: {len(clean_token)} (expected 64)"

        if not all(c in '0123456789abcdefABCDEF' for c in clean_token):
            return False, "Token contains invalid characters (must be hexadecimal)"

        return True, clean_token

# ==================== Initialize Handler ====================
apns = APNsHandler()

# ==================== API Routes ====================

@app.route('/debug/config', methods=['GET'])
def debug_config():
    """
    Debug endpoint to check configuration (DO NOT USE IN PRODUCTION)
    """
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
def send_notification():
    """
    Send push notification to an iOS device

    Expected JSON payload:
    {
        "device_token": "64-character hex token",
        "title": "Notification Title",
        "message": "Notification message body",
        "badge": 1,  // Optional
        "sound": "default",  // Optional
        "category": "MESSAGE_CATEGORY",  // Optional
        "thread_id": "thread-123",  // Optional for grouping
        "data": {  // Optional custom data
            "custom_key": "custom_value"
        },
        "priority": "high",  // Optional: "high" or "low"
        "collapse_id": "update-1",  // Optional: for replacing notifications
        "expiration": 1234567890  // Optional: Unix timestamp
    }
    """
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
        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Error in send_notification: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/send/batch', methods=['POST'])
def send_batch_notifications():
    """
    Send push notifications to multiple iOS devices

    Expected JSON payload:
    {
        "notifications": [
            {
                "device_token": "token1",
                "title": "Title 1",
                "message": "Message 1",
                "badge": 1,
                "data": {}
            },
            {
                "device_token": "token2",
                "title": "Title 2",
                "message": "Message 2"
            }
        ]
    }
    """
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

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "available_endpoints": [
            "GET /health",
            "POST /send",
            "POST /send/batch",
            "POST /validate/token"
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
    print(f"Port: {Config.PORT}")
    print("=" * 60)

    if not apns.auth_key:
        print("⚠️  WARNING: APNs authentication key not loaded!")
        print(f"   Please ensure {Config.APNS_AUTH_KEY_PATH} exists")
        print("=" * 60)

    app.run(
        host='0.0.0.0',
        port=Config.PORT,
        debug=Config.DEBUG
    )