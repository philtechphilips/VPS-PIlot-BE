"""Backups of apps' files (run by the privileged helper).

What an app keeps between deploys: the shared folder of a systemd app, the
data volume of a Docker app (vp-<app>-data) and the named volumes of a
Compose project. They are packed into one tar.gz, encrypted like database
backups (AES-256, key from the job secrets) and stored and uploaded the same
way, so retention, storage and the recovery kit work unchanged.

Restoring stops the app, empties each folder or volume, unpacks the backup
into it and starts the app again. Verification decrypts the backup and reads
every entry, without touching the app.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
from typing import Any

from vpspilot_agent import backups as b
from vpspilot_agent import deploy as d
from vpspilot_agent import native
from vpspilot_agent.errors import Rejected

EXT = "tar.gz.enc"


def data_volume(app: str) -> str:
    return f"vp-{app}-data"


def _args(args: dict[str, Any]) -> tuple[str, str, str, str]:
    app = d._match(d.APP_RE, args.get("app"), "app name")
    runtime = args.get("runtime")
    if runtime not in d.RUNTIMES:
        raise Rejected("invalid runtime")
    app_id = d._match(b.ID_RE, args.get("application_id"), "application")
    backup = d._match(b.ID_RE, args.get("backup_id"), "backup")
    return app, runtime, app_id, backup


def _mountpoint(volume: str) -> str | None:
    code, out = d._run(
        ["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", volume], timeout=15
    )
    path = out.strip()
    return path if code == 0 and path.startswith("/") else None


def sources(app: str, runtime: str) -> list[tuple[str, str]]:
    """(name in the archive, folder on this server) for what the app keeps."""
    if runtime == "systemd":
        shared = native._paths(app)["shared"]
        return [("shared", shared)] if os.path.isdir(shared) else []
    if runtime == "docker":
        names = [data_volume(app)]
    else:
        code, out = d._run(
            [
                "docker", "volume", "ls", "-q", "--filter",
                f"label=com.docker.compose.project=vp-{app}",
            ],
            timeout=15,
        )  # fmt: skip
        names = sorted(out.split()) if code == 0 else []
    found = []
    for name in names:
        path = _mountpoint(name)
        if path and os.path.isdir(path):
            found.append((f"volumes/{name}", path))
    return found


def _add_tree(tar: tarfile.TarFile, root: str, arc: str) -> tuple[int, int, int]:
    """Add a folder without following symlinks; files that vanish or can't
    be read mid-backup are skipped. Returns (files, bytes, skipped)."""
    files = size = skipped = 0
    tar.add(root, arcname=arc, recursive=False)
    for folder, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(dirs) + sorted(names):
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            try:
                info = tar.gettarinfo(path, arcname=f"{arc}/{rel}")
                if info is None:  # sockets
                    continue
                if info.isreg():
                    with open(path, "rb") as handle:
                        tar.addfile(info, handle)
                    files += 1
                    size += info.size
                else:
                    tar.addfile(info)
            except OSError:
                skipped += 1
    return files, size, skipped


def create(args: dict[str, Any], emit: b.Emit) -> dict[str, Any]:
    app, runtime, app_id, backup = _args(args)
    key = b._key(args)
    storage = b._storage(args)
    keep_local = args.get("keep_local", True) is not False or storage is None
    found = sources(app, runtime)
    if not found:
        hint = {
            "docker": "Set a data folder in the app's settings and redeploy",
            "systemd": "The app has no shared folder yet: deploy it first",
            "compose": "The Compose project has no named volumes",
        }[runtime]
        return {"exit_code": 1, "output": "", "error": f"Nothing to back up. {hint}."}
    folder = os.path.join(b.DIR, "apps", app_id)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(b.DIR, 0o700)
    path = os.path.join(folder, f"{backup}.{EXT}")
    emit("step", "Packing " + ", ".join(arc for arc, _ in found))
    with open(path, "wb") as out:
        proc = subprocess.Popen(
            b.OPENSSL,
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=subprocess.PIPE,
            env={**os.environ, "VPB_KEY": key},
        )
        files = size = skipped = 0
        try:
            assert proc.stdin is not None
            with tarfile.open(fileobj=proc.stdin, mode="w|gz") as tar:
                for arc, root in found:
                    f, s, k = _add_tree(tar, root, arc)
                    files, size, skipped = files + f, size + s, skipped + k
            proc.stdin.close()
        except (OSError, tarfile.TarError) as error:
            proc.kill()
            proc.wait()
            os.unlink(path)
            return {"exit_code": 1, "output": "", "error": f"Packing failed: {error}"}
        code = proc.wait(timeout=b.DUMP_TIMEOUT)
        stderr = (proc.stderr.read() if proc.stderr else b"").decode(errors="replace")
    if code != 0:
        os.unlink(path)
        return {"exit_code": 1, "output": "", "error": f"Encryption failed: {stderr[-300:]}"}
    os.chmod(path, 0o600)
    total, checksum = os.path.getsize(path), b._sha256(path)
    emit("info", f"{files} files ({size} bytes) packed into {total} encrypted bytes")
    if skipped:
        emit("warn", f"{skipped} files changed or vanished while packing and were skipped")
    remote = None
    try:
        if storage:
            emit("step", f"Uploading to {storage['label']}")
            remote = b._put(
                storage,
                b._remote_key(storage, "apps", app_id, backup, EXT),
                path,
                total,
            )
    except b.Failed as error:
        os.unlink(path)
        emit("error", str(error))
        return {"exit_code": 1, "output": "", "error": str(error)}
    if not keep_local:
        os.unlink(path)
    return {
        "exit_code": 0,
        "output": "",
        "result": {
            "path": path if keep_local else None,
            "remote_key": remote,
            "storage": storage["provider"] if storage else None,
            "size": total,
            "sha256": checksum,
            "files": files,
        },
    }


def _control(app: str, runtime: str, action: str) -> None:
    if runtime == "systemd":
        d._run(["systemctl", action, native.unit(app)], timeout=120)
    elif runtime == "compose":
        d._run(["docker", "compose", "-p", f"vp-{app}", action], timeout=300)
    else:
        d._run(["docker", action, f"vp-{app}"], timeout=120)


def _empty(root: str) -> None:
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)


def _inside(root: str, rel: str) -> bool:
    if not rel or os.path.isabs(rel) or ".." in rel.split("/"):
        return False
    parent = os.path.realpath(os.path.join(root, os.path.dirname(rel)))
    real_root = os.path.realpath(root)
    return parent == real_root or parent.startswith(real_root + os.sep)


def restore(args: dict[str, Any], emit: b.Emit) -> dict[str, Any]:
    """mode=verify: decrypt and read every entry; replace: put the files back."""
    app, runtime, _, _ = _args(args)
    key = b._key(args)
    mode = args.get("mode")
    if mode not in ("replace", "verify"):
        raise Rejected("invalid mode")
    targets = dict(sources(app, runtime)) if mode == "replace" else {}
    if mode == "replace" and runtime == "docker" and "volumes/" + data_volume(app) not in targets:
        d._run(["docker", "volume", "create", data_volume(app)], timeout=30)
        targets = dict(sources(app, runtime))
    path, temporary = None, False
    stopped = False
    try:
        path, temporary = b._fetch(args, emit)
        b._verify_checksum(path, args.get("sha256"))
        emit("info", "Checksum verified")
        with open(path, "rb") as encrypted:
            proc = subprocess.Popen(
                [*b.OPENSSL, "-d"],
                stdin=encrypted,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "VPB_KEY": key},
            )
            files = size = 0
            emptied: set[str] = set()
            missing: set[str] = set()
            try:
                assert proc.stdout is not None
                with tarfile.open(fileobj=proc.stdout, mode="r|gz") as tar:
                    for member in tar:
                        parts = member.name.split("/")
                        arc = "/".join(parts[:1] if parts[0] == "shared" else parts[:2])
                        rel = member.name[len(arc) + 1 :]
                        if member.isreg():
                            files += 1
                            size += member.size
                        if mode == "verify":
                            continue
                        root = targets.get(arc)
                        if root is None:
                            missing.add(arc)
                            continue
                        if not stopped:
                            emit("step", "Stopping the app")
                            _control(app, runtime, "stop")
                            stopped = True
                        if arc not in emptied:
                            emit("step", f"Restoring {arc}")
                            _empty(root)
                            emptied.add(arc)
                        if not rel or member.isdev() or member.isfifo():
                            continue
                        if not _inside(root, rel):
                            raise b.Failed(f"Unsafe path in the backup: {member.name}")
                        member.name = rel
                        if member.islnk():
                            link = member.linkname[len(arc) + 1 :]
                            if not member.linkname.startswith(arc + "/") or not _inside(root, link):
                                continue
                            member.linkname = link
                        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
                        tar.extract(member, root, **kwargs)
            finally:
                if proc.stdout:
                    proc.stdout.close()
                code = proc.wait()
            if code != 0:
                raise b.Failed("Couldn't decrypt the backup: wrong key or damaged file")
        for arc in sorted(missing):
            emit("warn", f"{arc} no longer exists here; skipped")
        summary = f"{files} files ({size} bytes)"
        emit("info", ("Backup is readable: " if mode == "verify" else "Restored ") + summary)
        return {
            "exit_code": 0,
            "output": json.dumps({"files": files, "bytes": size}),
            "result": {"files": files, "bytes": size},
        }
    except (b.Failed, tarfile.TarError, OSError) as error:
        message = str(error) if isinstance(error, b.Failed) else f"The backup is damaged: {error}"
        emit("error", message)
        return {"exit_code": 1, "output": "", "error": message}
    finally:
        if stopped:
            emit("step", "Starting the app")
            _control(app, runtime, "start")
        if temporary and path and os.path.exists(path):
            os.unlink(path)


STREAMING = {"backup.files": create, "backup.files_restore": restore}
