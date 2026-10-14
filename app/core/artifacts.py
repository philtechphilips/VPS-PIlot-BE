"""Temporary files that pass through the control plane (database exports
and imports), encrypted at rest and streamed in both directions.

Format: b"VPA1", an 8-byte key fingerprint, then chunks of
[4-byte length][12-byte nonce][AES-256-GCM ciphertext]. Each chunk's
associated data is its index and whether it is the last one, so chunks
can't be reordered, dropped or truncated without failing to decrypt.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import time
from collections.abc import AsyncIterator, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core import security
from app.core.config import settings

MAGIC = b"VPA1"
CHUNK = 1024 * 1024
NAME_RE = re.compile(r"[0-9a-f]{32}\.(in|out)")
MAX_AGE = 24 * 3600


class ArtifactError(Exception):
    pass


class TooLarge(ArtifactError):
    pass


def _key(master: str) -> bytes:
    return hashlib.sha256(f"vpspilot:artifacts:{master}".encode()).digest()


def _fingerprint(key: bytes) -> bytes:
    return hashlib.sha256(b"fingerprint" + key).digest()[:8]


def _dir() -> str:
    path = os.path.abspath(settings.artifacts_dir)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def path_for(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise ArtifactError("invalid artifact name")
    return os.path.join(_dir(), name)


def exists(name: str) -> bool:
    return os.path.isfile(path_for(name))


def size(name: str) -> int:
    """Approximate plaintext size."""
    try:
        total = os.path.getsize(path_for(name))
    except OSError:
        return 0
    chunks = max(1, -(-total // (CHUNK + 32)))
    return max(0, total - 12 - chunks * 32)


def _aad(index: int, last: bool) -> bytes:
    return struct.pack(">Q?", index, last)


async def write(name: str, chunks: AsyncIterator[bytes], limit: int) -> int:
    """Encrypt a stream into the artifact; returns the plaintext size."""
    key = _key(security._masters()[0])
    aes = AESGCM(key)
    final = path_for(name)
    tmp = f"{final}.part"
    total = 0
    index = 0
    pending = b""
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(MAGIC + _fingerprint(key))

            def seal(data: bytes, last: bool) -> None:
                nonlocal index
                nonce = os.urandom(12)
                body = aes.encrypt(nonce, data, _aad(index, last))
                out.write(struct.pack(">I", len(body)) + nonce + body)
                index += 1

            async for chunk in chunks:
                total += len(chunk)
                if total > limit:
                    raise TooLarge(f"Larger than {limit // (1024 * 1024)} MB")
                pending += chunk
                # Keep one chunk back: only at the end is it known to be last.
                while len(pending) > CHUNK:
                    seal(pending[:CHUNK], False)
                    pending = pending[CHUNK:]
            seal(pending, True)
        os.replace(tmp, final)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return total


def read(name: str) -> Iterator[bytes]:
    """Decrypt the artifact chunk by chunk."""
    path = path_for(name)
    with open(path, "rb") as handle:
        header = handle.read(12)
        if header[:4] != MAGIC:
            raise ArtifactError("not an artifact")
        key = next(
            (
                k
                for k in (_key(m) for m in security._masters())
                if _fingerprint(k) == header[4:]
            ),
            None,
        )
        if key is None:
            raise ArtifactError("encrypted with a key that's no longer configured")
        aes = AESGCM(key)
        index = 0
        while True:
            head = handle.read(4)
            if len(head) < 4:
                raise ArtifactError("truncated")
            (length,) = struct.unpack(">I", head)
            nonce = handle.read(12)
            body = handle.read(length)
            last = handle.peek(1)[:1] == b"" if hasattr(handle, "peek") else False
            try:
                yield aes.decrypt(nonce, body, _aad(index, last))
            except InvalidTag:
                raise ArtifactError("damaged or tampered with") from None
            index += 1
            if last:
                return


def delete(name: str) -> None:
    try:
        os.unlink(path_for(name))
    except (OSError, ArtifactError):
        pass


def prune(max_age: int = MAX_AGE) -> int:
    """Remove artifacts older than max_age seconds."""
    removed = 0
    cutoff = time.time() - max_age
    for entry in os.scandir(_dir()):
        if entry.is_file() and entry.stat().st_mtime < cutoff:
            os.unlink(entry.path)
            removed += 1
    return removed
