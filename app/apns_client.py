from __future__ import annotations
import time
import json
import httpx
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import hmac

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _jwt_es256(team_id: str, key_id: str, p8_pem: str) -> str:
    """
    Minimal ES256 JWT for APNs.
    p8_pem is the content of your AuthKey_XXXXXX.p8 file.
    """
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    payload = {"iss": team_id, "iat": int(time.time())}

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    private_key = serialization.load_pem_private_key(
        p8_pem.encode(),
        password=None,
        backend=default_backend(),
    )

    # cryptography signs with DER-encoded ECDSA; APNs accepts standard JWS ECDSA signature
    # We'll use cryptography's sign and then convert DER->raw (r||s) per JWS.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    sig_der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

    # DER to raw r||s
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig_der)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    sig_raw = r_bytes + s_bytes

    return f"{header_b64}.{payload_b64}.{_b64url(sig_raw)}"

class ApnsClient:
    def __init__(
            self,
            team_id: str,
            key_id: str,
            p8_pem: str,
            bundle_id: str,
            use_sandbox: bool = False,
    ):
        self.team_id = team_id
        self.key_id = key_id
        self.p8_pem = p8_pem
        self.bundle_id = bundle_id
        self.base = "https://api.sandbox.push.apple.com" if use_sandbox else "https://api.push.apple.com"

    async def send(
            self,
            device_token: str,
            title: str,
            body: str,
            *,
            data: Optional[Dict[str, Any]] = None,
    ) -> tuple[int, str]:
        jwt = _jwt_es256(self.team_id, self.key_id, self.p8_pem)

        # Standard APS payload
        payload: Dict[str, Any] = {
            "aps": {
                "alert": {"title": title, "body": body},
                "sound": "default",
            }
        }
        if data:
            payload["data"] = data

        headers = {
            "authorization": f"bearer {jwt}",
            "apns-topic": self.bundle_id,  # your iOS app bundle id
        }

        url = f"{self.base}/3/device/{device_token}"

        async with httpx.AsyncClient(http2=True, timeout=10.0) as client:
            r = await client.post(url, headers=headers, json=payload)

        return r.status_code, r.text