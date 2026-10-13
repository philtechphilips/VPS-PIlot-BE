from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    project_name: str = "VPSPilot API"

    database_hostname: str
    database_port: int = 5432
    database_password: str
    database_name: str
    database_username: str

    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    password_reset_token_expire_minutes: int = 30

    # Used to build links in emails, e.g. the password reset link
    frontend_url: str = "http://localhost:3000"

    # JSON list in .env, e.g. CORS_ORIGINS=["http://localhost:3000"]
    cors_origins: list[str] = ["*"]

    @property
    def database_url(self) -> URL:
        # URL.create escapes special characters in the password.
        return URL.create(
            drivername="postgresql+psycopg2",
            username=self.database_username,
            password=self.database_password,
            host=self.database_hostname,
            port=self.database_port,
            database=self.database_name,
        )


settings = Settings()
