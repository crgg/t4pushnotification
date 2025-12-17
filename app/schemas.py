from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class SendNotificationRequest(BaseModel):
    user_id: int = Field(..., ge=1)
    message: str = Field(..., min_length=1, max_length=4000)

    # Optional ntfy fields
    title: Optional[str] = Field(default=None, max_length=200)
    priority: Optional[int] = Field(default=None, ge=1, le=5)  # 1..5 in ntfy
    tags: Optional[list[str]] = None
    click: Optional[str] = None  # URL
    actions: Optional[str] = None  # advanced; can pass raw string if you want

    # Optional custom metadata
    data: Optional[Dict[str, Any]] = None

class SendNotificationResponse(BaseModel):
    ok: bool
    user_id: int
    topic: str
    ntfy_status_code: int
    ntfy_response: Optional[Dict[str, Any]] = None

class SendNotificationDeviceToken(BaseModel):
    device_token: str = Field(default=None)
    message: str = Field(default=None)
    title: str = Field(default=None)