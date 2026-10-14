"""Minimal JSON-over-HTTPS client (standard library only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from vpspilot_agent import __version__


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class NotEnrolled(ApiError):
    """401 from the control plane: the credential was revoked or is unknown."""


class Client:
    def __init__(self, api_url: str, token: str | None = None, timeout: float = 10):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._send("POST", path, json.dumps(body, default=str).encode())

    def get(self, path: str) -> dict[str, Any]:
        return self._send("GET", path, None)

    def _send(self, method: str, path: str, data: bytes | None) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"vpspilot-agent/{__version__}",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            message = _detail(error.read())
            if error.code == 401:
                raise NotEnrolled(401, message) from None
            raise ApiError(error.code, message) from None
        return json.loads(raw) if raw else {}


def _detail(raw: bytes) -> str:
    try:
        detail = json.loads(raw).get("detail")
        return detail if isinstance(detail, str) else json.dumps(detail)[:300]
    except (ValueError, AttributeError):
        return raw[:300].decode(errors="replace")
