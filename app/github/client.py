"""Thin GitHub REST client. Everything goes through request(), which tests
replace with a fake."""

from typing import Any

import httpx

API = "https://api.github.com"
WEB = "https://github.com"


class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


def request(
    method: str,
    path: str,
    token: str | None = None,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VPSPilot",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.request(
            method,
            f"{API}{path}",
            headers=headers,
            json=json,
            params=params,
            timeout=15,
        )
    except httpx.HTTPError as error:
        raise GitHubError(502, f"GitHub unreachable: {error}") from error
    if response.status_code >= 400:
        try:
            message = response.json().get("message") or response.text[:200]
        except ValueError:
            message = response.text[:200]
        raise GitHubError(response.status_code, message)
    return response.json() if response.content else None
