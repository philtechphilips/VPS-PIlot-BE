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
    # Key for encrypting stored secrets (env vars, TOTP, GitHub keys, job
    # output). Generate with `python -m app.encryption generate-key`. When
    # empty, a key derived from SECRET_KEY is used (older installs).
    # Old keys go in ENCRYPTION_KEYS_PREVIOUS (comma separated) during a
    # rotation, then `python -m app.encryption rotate` re-encrypts.
    encryption_key: str = ""
    encryption_keys_previous: str = ""
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

    # Agents: the URL agents use to reach this API (what the install command
    # contains). In the local Lima lab that is http://host.lima.internal:8000.
    agent_api_url: str = "http://localhost:8000"
    agent_heartbeat_seconds: int = 10
    agent_metrics_seconds: int = 15
    # A server is shown offline when no heartbeat arrived for this long.
    agent_offline_after_seconds: int = 35
    enrollment_token_expire_minutes: int = 15
    metrics_retention_days: int = 7
    # Alert rules are evaluated in the API process this often (0 disables).
    alerts_evaluate_seconds: int = 30

    # Database exports and imports pass through here, encrypted, for a day.
    artifacts_dir: str = "data/artifacts"
    max_transfer_mb: int = 1024

    # Used to build links in emails, e.g. the password reset link
    frontend_url: str = "http://localhost:3000"

    # Public https URL of this API, used for GitHub webhooks (push to deploy).
    # Falls back to AGENT_API_URL when that is https (e.g. an ngrok tunnel).
    public_api_url: str = ""

    @property
    def webhook_base_url(self) -> str | None:
        for url in (self.public_api_url, self.agent_api_url):
            if url.startswith("https://"):
                return url.rstrip("/")
        return None

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
