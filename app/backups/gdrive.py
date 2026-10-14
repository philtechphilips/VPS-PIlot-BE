"""Google Drive as backup storage, through the owner's own OAuth client.

VPSPilot asks only for drive.file: it sees nothing in Drive except the
files and folder it creates. The refresh token stays here, encrypted;
backup jobs get a short-lived access token with their secrets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy.orm import Session

from app.backups.models import BackupSettings
from app.core.config import settings
from app.core.security import decrypt_secret, encrypt_secret

PURPOSE = "backup"
SCOPE = "https://www.googleapis.com/auth/drive.file"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
API = "https://www.googleapis.com"
FOLDER_NAME = "VPSPilot backups"
STATE_TTL = 15 * 60
TIMEOUT = 20

# refresh-token fingerprint -> (access token, expiry)
_tokens: dict[str, tuple[str, float]] = {}


class DriveError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def redirect_uri() -> str:
    """Where Google sends the owner back: the dashboard's address (the
    /api path reaches this API through it, in dev and self-hosted)."""
    return f"{settings.frontend_url.rstrip('/')}/api/v1/backups/gdrive/callback"


# ---------------------------------------------------------------------------
# OAuth state (signed; the callback is a plain browser redirect)
# ---------------------------------------------------------------------------


def _sign(data: bytes) -> str:
    key = hashlib.sha256(f"vpspilot:gdrive-state:{settings.secret_key}".encode())
    return hmac.new(key.digest(), data, hashlib.sha256).hexdigest()


def make_state(user_id: int) -> str:
    body = json.dumps(
        {"u": user_id, "exp": int(time.time()) + STATE_TTL, "n": secrets.token_hex(8)}
    ).encode()
    encoded = base64.urlsafe_b64encode(body).decode().rstrip("=")
    return f"{encoded}.{_sign(body)}"


def read_state(state: str) -> int:
    try:
        encoded, signature = state.split(".", 1)
        body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        data = json.loads(body)
    except (ValueError, TypeError):
        raise DriveError(
            400, "That sign-in link is broken; try connecting again"
        ) from None
    if not hmac.compare_digest(_sign(body), signature):
        raise DriveError(400, "That sign-in link is broken; try connecting again")
    if data.get("exp", 0) < time.time():
        raise DriveError(400, "That sign-in took too long; try connecting again")
    return int(data["u"])


# ---------------------------------------------------------------------------
# Tokens and API calls
# ---------------------------------------------------------------------------


def _client(row: BackupSettings) -> tuple[str, str]:
    if not (row.gdrive_client_id and row.gdrive_client_secret):
        raise DriveError(422, "Save the OAuth client ID and secret first")
    return row.gdrive_client_id, decrypt_secret(row.gdrive_client_secret, PURPOSE)


def auth_url(row: BackupSettings, user_id: int) -> str:
    client_id, _ = _client(row)
    return f"{AUTH_URL}?" + urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri(),
            "response_type": "code",
            "scope": SCOPE,
            "access_type": "offline",
            "prompt": "consent",  # always return a refresh token
            "include_granted_scopes": "false",
            "state": make_state(user_id),
        }
    )


def _post_token(data: dict[str, str]) -> dict[str, Any]:
    try:
        response = httpx.post(TOKEN_URL, data=data, timeout=TIMEOUT)
    except httpx.HTTPError as error:
        raise DriveError(
            502, f"Couldn't reach Google: {type(error).__name__}"
        ) from None
    body = response.json() if response.content else {}
    if response.status_code != 200:
        reason = (
            body.get("error_description") or body.get("error") or response.text[:150]
        )
        if body.get("error") == "invalid_grant":
            reason = "Google revoked VPSPilot's access; connect Google Drive again"
        raise DriveError(502, f"Google said: {reason}")
    return body


def _api(token: str, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    try:
        response = httpx.request(
            method,
            f"{API}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT,
            **kwargs,
        )
    except httpx.HTTPError as error:
        raise DriveError(
            502, f"Couldn't reach Google Drive: {type(error).__name__}"
        ) from None
    if response.status_code >= 300:
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = response.text[:150]
        raise DriveError(502, f"Google Drive said: {message}")
    return response.json() if response.content else {}


def connect(row: BackupSettings, code: str) -> None:
    """Finish sign-in: keep the refresh token, find the account and make
    (or reuse) the backups folder."""
    client_id, client_secret = _client(row)
    tokens = _post_token(
        {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri(),
            "grant_type": "authorization_code",
        }
    )
    refresh = tokens.get("refresh_token")
    if not refresh:
        raise DriveError(
            502, "Google didn't grant offline access; try connecting again"
        )
    access = tokens["access_token"]
    about = _api(
        access, "GET", "/drive/v3/about", params={"fields": "user(emailAddress)"}
    )
    folder = row.gdrive_folder_id
    if folder:
        try:
            _api(
                access,
                "GET",
                f"/drive/v3/files/{folder}",
                params={"fields": "id,trashed"},
            )
        except DriveError:
            folder = None  # a different account, or the folder was deleted
    if not folder:
        folder = _api(
            access,
            "POST",
            "/drive/v3/files",
            params={"fields": "id"},
            json={
                "name": FOLDER_NAME,
                "mimeType": "application/vnd.google-apps.folder",
            },
        )["id"]
    row.gdrive_refresh_token = encrypt_secret(refresh, PURPOSE)
    row.gdrive_account = (
        str((about.get("user") or {}).get("emailAddress") or "")[:200] or None
    )
    row.gdrive_folder_id = folder
    _tokens.clear()


def access_token(row: BackupSettings) -> str:
    """A short-lived token for one backup job (cached until near expiry)."""
    if not row.gdrive_refresh_token:
        raise DriveError(422, "Connect Google Drive first")
    refresh = decrypt_secret(row.gdrive_refresh_token, PURPOSE)
    key = hashlib.sha256(refresh.encode()).hexdigest()
    cached = _tokens.get(key)
    if cached and cached[1] > time.time() + 300:
        return cached[0]
    client_id, client_secret = _client(row)
    body = _post_token(
        {
            "refresh_token": refresh,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
        }
    )
    token = body["access_token"]
    _tokens[key] = (token, time.time() + int(body.get("expires_in", 3600)))
    return token


def disconnect(db: Session, row: BackupSettings) -> None:
    if row.gdrive_refresh_token:
        try:
            httpx.post(
                REVOKE_URL,
                data={"token": decrypt_secret(row.gdrive_refresh_token, PURPOSE)},
                timeout=TIMEOUT,
            )
        except httpx.HTTPError:
            pass  # forget it here regardless
    row.gdrive_refresh_token = None
    row.gdrive_account = None
    if row.provider == "gdrive":
        row.storage_enabled = False
    _tokens.clear()
    db.commit()
