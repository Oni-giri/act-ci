"""Encryption at rest, token hashing, CSRF tokens, and secret masking."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import urllib.parse
from pathlib import Path
from typing import Iterable

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive_fernet_key(raw_material: bytes, context: bytes = b"act-ci-fernet-v1") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"act-ci-static-salt-v1",
        info=context,
    )
    return base64.urlsafe_b64encode(hkdf.derive(raw_material))


class SecretBox:
    """Encrypts and decrypts credentials, workflow secrets, and overlays at rest."""

    def __init__(self, master_secret: str) -> None:
        if not master_secret or len(master_secret.strip()) < 16:
            raise ValueError("Master secret must be at least 16 characters")
        self._raw = master_secret.encode("utf-8")
        self._fernet = Fernet(_derive_fernet_key(self._raw))

    @classmethod
    def from_data_dir(cls, data_dir: Path, env_key: str | None = None) -> "SecretBox":
        if env_key and len(env_key.strip()) >= 16:
            return cls(env_key.strip())
        data_dir.mkdir(parents=True, exist_ok=True)
        key_file = data_dir / "master.key"
        if key_file.exists():
            stored = key_file.read_text(encoding="utf-8").strip()
            return cls(stored)
        generated = secrets.token_hex(32)
        fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (generated + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return cls(generated)

    def encrypt_str(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt_str(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")

    def encrypt_dict(self, data: dict[str, str]) -> str:
        if not data:
            return ""
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return self.encrypt_str(payload)

    def decrypt_dict(self, ciphertext: str) -> dict[str, str]:
        if not ciphertext:
            return {}
        raw = self.decrypt_str(ciphertext)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return {}
        return {str(k): str(v) for k, v in parsed.items()}

    def derive_csrf_secret(self, explicit_csrf: str | None = None) -> bytes:
        if explicit_csrf and len(explicit_csrf.strip()) >= 16:
            return explicit_csrf.strip().encode("utf-8")
        return hmac.new(self._raw, b"act-ci-csrf-v1", hashlib.sha256).digest()


def generate_api_token() -> tuple[str, str, str]:
    """Return (raw_token, token_hash, token_prefix). Raw token is shown only once."""
    body = secrets.token_urlsafe(32)
    raw_token = f"actci_{body}"
    token_hash = hash_api_token(raw_token)
    token_prefix = raw_token[:12]
    return raw_token, token_hash, token_prefix


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class CsrfSigner:
    """Stateless per-install HMAC CSRF token signer."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def issue(self) -> str:
        nonce = secrets.token_hex(16)
        sig = hmac.new(self._secret, nonce.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{nonce}.{sig}"

    def verify(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        nonce, sig = token.split(".", 1)
        if len(nonce) != 32 or len(sig) != 64:
            return False
        expected = hmac.new(self._secret, nonce.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)


class SecretMasker:
    """Masks sensitive credential and secret values in log lines and error messages."""

    def __init__(self, secrets_iter: Iterable[str]) -> None:
        candidates: set[str] = set()
        for item in secrets_iter:
            if not item:
                continue
            for variant in self._variants(item):
                if variant and len(variant) >= 3:
                    candidates.add(variant)
        # Longest-first prevents partial-prefix leaks on overlapping secrets
        self._needles = sorted(candidates, key=len, reverse=True)

    @staticmethod
    def _variants(val: str) -> list[str]:
        out = [val]
        stripped = val.strip()
        if stripped and stripped != val:
            out.append(stripped)
        # Multi-line secrets (like SSH deploy keys): mask every non-trivial line too
        for line in val.splitlines():
            s = line.strip()
            if len(s) >= 6 and not s.startswith("-----"):
                out.append(s)
        if len(stripped) >= 4:
            url_enc = urllib.parse.quote(stripped, safe="")
            if url_enc != stripped:
                out.append(url_enc)
            b64 = base64.b64encode(stripped.encode("utf-8")).decode("ascii")
            out.append(b64)
        return out

    def mask(self, text: str | None) -> str:
        if not text:
            return ""
        masked = text
        for needle in self._needles:
            if needle in masked:
                masked = masked.replace(needle, "***")
        return masked
