from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = Field(default="push-service", alias="APP_NAME")
    env: str = Field(default="local", alias="ENV")

    database_url: str = Field(alias="DATABASE_URL")

    ntfy_base_url: str = Field(default="https://ntfy.sh", alias="NTFY_BASE_URL")
    ntfy_auth_mode: str = Field(default="none", alias="NTFY_AUTH_MODE")  # none|basic
    ntfy_username: str | None = Field(default=None, alias="NTFY_USERNAME")
    ntfy_password: str | None = Field(default=None, alias="NTFY_PASSWORD")

    api_key: str | None = Field(default=None, alias="API_KEY")
    apns_team_id:str =Field(default="")
    apns_key_id:str =Field(default="")
    apns_p8_pem:str =Field(default="")
    apns_bundle_id:str =Field(default="")
    apns_sandbox:str =Field(default="")

settings = Settings()