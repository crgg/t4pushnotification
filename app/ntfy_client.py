from __future__ import annotations
from typing import Optional, Dict, Any
import httpx
from .config import settings

class NtfyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _auth(self) -> Optional[tuple[str, str]]:
        if settings.ntfy_auth_mode.lower() == "basic":
            if not settings.ntfy_username or not settings.ntfy_password:
                raise RuntimeError("NTFY basic auth enabled but username/password not set")
            return (settings.ntfy_username, settings.ntfy_password)
        return None

    async def publish(
            self,
            topic: str,
            message: str,
            *,
            title: str | None = None,
            priority: int | None = None,
            tags: list[str] | None = None,
            click: str | None = None,
            actions: str | None = None,
            data: Dict[str, Any] | None = None,
    ) -> tuple[int, Dict[str, Any] | None]:
        """
        Publishes to: POST {base_url}/{topic}
        Uses headers for title/priority/tags/click/actions per ntfy API.
        """
        url = f"{self.base_url}/{topic}"

        headers: dict[str, str] = {}
        if title:
            headers["Title"] = title
        if priority:
            headers["Priority"] = str(priority)
        if tags:
            headers["Tags"] = ",".join(tags)
        if click:
            headers["Click"] = click
        if actions:
            headers["Actions"] = actions

        # If you want to attach JSON metadata, you can embed it in the message or use headers.
        # ntfy supports "X-*" custom headers; this is a pragmatic approach.
        if data:
            for k, v in data.items():
                headers[f"X-Data-{k}"] = str(v)

        auth = self._auth()

        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, content=message.encode("utf-8"), headers=headers, auth=auth)

        # ntfy typically returns JSON for some endpoints; publish may return text.
        resp_json: Dict[str, Any] | None = None
        try:
            resp_json = r.json()
        except Exception:
            resp_json = None

        return r.status_code, resp_json