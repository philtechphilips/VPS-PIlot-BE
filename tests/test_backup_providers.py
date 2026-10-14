"""Backup storage providers: Google Drive (and S3 presets like R2)."""

import http.server
import json
import os
import re
import threading
import time

import pytest
from sqlalchemy.orm import Session
from vpspilot_agent import backups as agent_backups

from app.backups import gdrive
from app.backups import service as backups
from app.backups.models import BackupRun
from tests.test_backups import BK, finish
from tests.test_databases import managed
from tests.test_jobs import claim

CLIENT_ID = "123456789-abcdef.apps.googleusercontent.com"


# ---------------------------------------------------------------------------
# Agent: Drive's resumable upload protocol against a fake Drive
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_drive(monkeypatch):
    files: dict[str, bytes] = {}
    sessions: dict[str, dict] = {}
    seen_tokens = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))

        def do_POST(self):
            seen_tokens.append(self.headers.get("Authorization"))
            meta = json.loads(self._body())
            sid = f"s{len(sessions)}"
            sessions[sid] = {
                "name": meta["name"],
                "size": int(self.headers["X-Upload-Content-Length"]),
                "data": b"",
            }
            self.send_response(200)
            self.send_header(
                "Location", f"{base}/upload/drive/v3/files?upload_id={sid}"
            )
            self.end_headers()

        def do_PUT(self):
            sid = re.search(r"upload_id=(\w+)", self.path).group(1)
            session = sessions[sid]
            chunk = self._body()
            start = int(
                re.match(r"bytes (\d+)-", self.headers["Content-Range"]).group(1)
            )
            assert start == len(session["data"])
            session["data"] += chunk
            if len(session["data"]) < session["size"]:
                self.send_response(308)
                self.send_header("Range", f"bytes=0-{len(session['data']) - 1}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            file_id = f"file{len(files):010d}"
            files[file_id] = session["data"]
            body = json.dumps({"id": file_id}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            file_id = re.search(r"files/(\w+)\?alt=media", self.path).group(1)
            self.send_response(200)
            self.send_header("Content-Length", str(len(files[file_id])))
            self.end_headers()
            self.wfile.write(files[file_id])

        def do_DELETE(self):
            files.pop(self.path.rsplit("/", 1)[1])
            self.send_response(204)
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(agent_backups, "DRIVE_API", base)
    monkeypatch.setattr(agent_backups, "DRIVE_CHUNK", 256 * 1024)
    yield files, seen_tokens
    server.shutdown()


def test_agent_uploads_downloads_and_deletes_on_drive(fake_drive, tmp_path):
    files, tokens = fake_drive
    storage = agent_backups._storage(
        {
            "storage": {"provider": "gdrive", "folder_id": "folder0123456789"},
            "secrets": {"gdrive_token": "ya29.test-access-token-1234567890"},
        }
    )
    data = os.urandom(700 * 1024)  # three chunks
    path = tmp_path / "backup.enc"
    path.write_bytes(data)
    file_id = agent_backups._put(
        storage, "inst/main/run.pgdump.enc", str(path), len(data)
    )
    assert files[file_id] == data
    assert tokens == ["Bearer ya29.test-access-token-1234567890"]
    out = tmp_path / "down.enc"
    agent_backups._get(storage, file_id, str(out))
    assert out.read_bytes() == data
    agent_backups._remove(storage, file_id)
    assert files == {}


def test_agent_refuses_drive_without_a_token():
    with pytest.raises(agent_backups.Rejected):
        agent_backups._storage(
            {"storage": {"provider": "gdrive", "folder_id": "folder0123456789"}}
        )
    with pytest.raises(agent_backups.Rejected):
        agent_backups._storage({"storage": {"provider": "ftp"}, "secrets": {}})


# ---------------------------------------------------------------------------
# Control plane: sign-in, tokens, runs
# ---------------------------------------------------------------------------


def test_state_is_signed_and_expires(monkeypatch):
    state = gdrive.make_state(7)
    assert gdrive.read_state(state) == 7
    body, sig = state.split(".")
    with pytest.raises(gdrive.DriveError):
        gdrive.read_state(f"{body}.{'0' * len(sig)}")
    monkeypatch.setattr(time, "time", lambda: 10**10)
    with pytest.raises(gdrive.DriveError, match="too long"):
        gdrive.read_state(state)


@pytest.fixture
def google(monkeypatch):
    calls = []

    def post_token(data):
        calls.append(data["grant_type"])
        if data["grant_type"] == "authorization_code":
            assert (
                data["code"] == "the-code"
                and data["redirect_uri"] == gdrive.redirect_uri()
            )
            return {
                "access_token": "ya29.first-access-token-123456",
                "refresh_token": "1//refresh-token",
            }
        return {
            "access_token": f"ya29.refreshed-token-{len(calls)}-abcdefgh",
            "expires_in": 3600,
        }

    def api(token, method, path, **kwargs):
        if path.endswith("/about"):
            return {"user": {"emailAddress": "owner@example.com"}}
        if method == "POST":
            return {"id": "folder0123456789"}
        return {"id": "folder0123456789"}

    monkeypatch.setattr(gdrive, "_post_token", post_token)
    monkeypatch.setattr(gdrive, "_api", api)
    gdrive._tokens.clear()
    return calls


def _connect(client, admin_headers):
    saved = client.put(
        f"{BK}/settings",
        json={"gdrive_client_id": CLIENT_ID, "gdrive_client_secret": "GOCSPX-secret"},
        headers=admin_headers,
    )
    assert saved.status_code == 200, saved.text
    url = client.post(f"{BK}/gdrive/connect", headers=admin_headers).json()["url"]
    assert "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file" in url
    assert "access_type=offline" in url
    state = re.search(r"state=([^&]+)", url).group(1)
    return client.get(
        f"{BK}/gdrive/callback", params={"state": state, "code": "the-code"},
        follow_redirects=False,
    )  # fmt: skip


def test_connecting_drive_and_backing_up_to_it(
    client, admin_headers, db: Session, google
):
    instance, agent, _ = managed(client, admin_headers)
    early = client.put(f"{BK}/settings", json={"storage_enabled": True, "provider": "gdrive"},
                       headers=admin_headers)  # fmt: skip
    assert early.status_code == 422  # not connected yet

    back = _connect(client, admin_headers)
    assert back.status_code == 303 and "gdrive=connected" in back.headers["location"]
    settings = client.get(f"{BK}/settings", headers=admin_headers).json()
    assert settings["provider"] == "gdrive" and settings["storage_enabled"] is True
    assert settings["gdrive"]["account"] == "owner@example.com"
    assert "GOCSPX-secret" not in json.dumps(
        settings
    ) and "refresh-token" not in json.dumps(settings)

    runs = client.post(
        f"{BK}/run", json={"instance_id": instance["id"]}, headers=admin_headers
    ).json()
    job = claim(client, agent)
    assert job["payload"]["storage"] == {
        "provider": "gdrive",
        "folder_id": "folder0123456789",
    }
    secrets = client.get(f"/agent/v1/jobs/{job['id']}/secrets", headers=agent).json()[
        "secrets"
    ]
    assert secrets["gdrive_token"].startswith("ya29.refreshed-token")
    assert "s3_access_key" not in secrets
    finish(client, agent, job["id"], result={"path": None, "remote_key": "file0123456789",
                                               "storage": "gdrive", "size": 2000, "sha256": "b" * 64})  # fmt: skip
    run = db.get(BackupRun, runs[0]["id"])
    assert (run.remote_key, run.storage) == ("file0123456789", "gdrive")

    # Switch new backups to S3: restoring this one still reads from Drive.
    client.put(
        f"{BK}/settings",
        json={"provider": "s3", "endpoint": "https://abc123.r2.cloudflarestorage.com",
              "region": "auto", "bucket": "backups", "access_key": "AK", "secret_key": "SK"},
        headers=admin_headers,
    )  # fmt: skip
    restore = client.post(f"{BK}/{run.id}/restore", json={"mode": "new", "into": "copy"},
                          headers=admin_headers)  # fmt: skip
    assert restore.status_code == 202, restore.text
    job = claim(client, agent)
    assert job["payload"]["storage"]["provider"] == "gdrive"

    off = client.delete(f"{BK}/gdrive/connection", headers=admin_headers).json()
    assert off["gdrive"]["connected"] is False and off["provider"] == "s3"


def test_callback_rejects_forged_or_cancelled_sign_in(client, admin_headers, google):
    bad = client.get(f"{BK}/gdrive/callback", params={"state": "x.y", "code": "c"},
                     follow_redirects=False)  # fmt: skip
    assert bad.status_code == 303 and "gdrive_error" in bad.headers["location"]
    client.put(f"{BK}/settings", json={"gdrive_client_id": CLIENT_ID, "gdrive_client_secret": "s"},
               headers=admin_headers)  # fmt: skip
    url = client.post(f"{BK}/gdrive/connect", headers=admin_headers).json()["url"]
    state = re.search(r"state=([^&]+)", url).group(1)
    cancelled = client.get(f"{BK}/gdrive/callback", params={"state": state, "error": "access_denied"},
                           follow_redirects=False)  # fmt: skip
    assert "cancelled" in cancelled.headers["location"]
    assert backups.get_settings  # settings untouched
    assert (
        client.get(f"{BK}/settings", headers=admin_headers).json()["gdrive"][
            "connected"
        ]
        is False
    )
