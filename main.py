from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.config import settings
from app.db import Base, engine, get_db
from app.models import Device
from app.schemas import SendNotificationRequest, SendNotificationResponse
from app.ntfy_client import NtfyClient

app = FastAPI(title=settings.app_name)

# Create tables (for dev). In production, use Alembic migrations.
Base.metadata.create_all(bind=engine)

ntfy = NtfyClient(settings.ntfy_base_url)

def require_api_key(x_api_key: str | None):
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.post("/notifications/send", response_model=SendNotificationResponse)
async def send_notification(
        payload: SendNotificationRequest,
        db: Session = Depends(get_db),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    require_api_key(x_api_key)

    stmt = select(Device).where(Device.user_id == payload.user_id)
    device = db.execute(stmt).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail=f"No device token found for user_id={payload.user_id}")

    topic = device.token.strip()
    if not topic:
        raise HTTPException(status_code=400, detail="Device token/topic is empty")

    status_code, resp_json = await ntfy.publish(
        topic=topic,
        message=payload.message,
        title=payload.title,
        priority=payload.priority,
        tags=payload.tags,
        click=payload.click,
        actions=payload.actions,
        data=payload.data,
    )

    if status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "Failed to publish to ntfy",
                "ntfy_status_code": status_code,
                "ntfy_response": resp_json,
            },
        )

    return SendNotificationResponse(
        ok=True,
        user_id=payload.user_id,
        topic=topic,
        ntfy_status_code=status_code,
        ntfy_response=resp_json,
    )