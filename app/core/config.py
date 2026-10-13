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
    # Access tokens are short-lived; the refresh cookie keeps the session going.
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    refresh_cookie_name: str = "vp_refresh"
    # Set to true in production so the refresh cookie is only sent over HTTPS.
    cookie_secure: bool = False
    password_reset_token_expire_minutes: int = 30

    # Two-factor codes sent by email
    two_factor_code_expire_minutes: int = 10
    two_factor_max_attempts: int = 5
    two_factor_resend_cooldown_seconds: int = 30

    # Login throttling: lock the account after this many wrong passwords
    login_max_failed_attempts: int = 5
    login_lockout_minutes: int = 15

    # Email delivery through Resend (https://resend.com). Without an API key,
    # emails are written to the log instead, which is handy in development.
    resend_api_key: str = ""
    email_from: str = "VPSPilot <onboarding@resend.dev>"
    # Resend's test sender can only deliver to the account owner's address.
    # When set, every email goes here instead (the real recipient is kept in
    # the subject), so the whole flow can be tested before a domain is verified.
    email_override_to: str | None = None

    # Used to build links in emails, e.g. the password reset link
    frontend_url: str = "http://localhost:3000"

    # JSON list in .env, e.g. CORS_ORIGINS=["http://localhost:3000"]
    cors_origins: list[str] = ["http://localhost:3000"]

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
