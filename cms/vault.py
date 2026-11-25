"""Encryption for contact messages, and keyed one-way codes for looking things up.

Two jobs:

* encrypt() / decrypt(): the name, email address, message, IP address and browser text of a contact
  message are stored encrypted (Fernet: AES with an integrity check). Someone who gets a copy of the
  database sees only scrambled text.
* blind(): a keyed one-way code (HMAC-SHA256). The spam limits need to ask "has this IP, email or browser
  sent something recently?" without storing any of them readably, so they compare these codes instead.
  Without the key the codes can't be turned back into an IP address, even though IP addresses are easy to
  guess one by one.

The key is never stored in the database. It comes from MESSAGE_ENCRYPTION_KEY (any long random string), or,
if that isn't set, from SECRET_KEY. To change the key without locking yourself out of old messages, put the
new one in MESSAGE_ENCRYPTION_KEY and the previous one(s) in MESSAGE_ENCRYPTION_KEY_OLD (comma separated).

If no real key is available, ready() is False and the contact form refuses to store messages rather than
storing them in the clear.
"""
import base64
import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PLACEHOLDERS = {"", "dev-key-change-in-production", "your_random_secret_key_here"}
_PREFIX = "v1:"


def _masters() -> tuple:
    """Current secret first, then older ones that may still be needed to read old messages."""
    current = os.environ.get("MESSAGE_ENCRYPTION_KEY", "").strip()
    if current in _PLACEHOLDERS:
        current = os.environ.get("SECRET_KEY", "").strip()
    if current in _PLACEHOLDERS:
        return ()
    old = [k.strip() for k in os.environ.get("MESSAGE_ENCRYPTION_KEY_OLD", "").split(",")]
    return (current, *[k for k in old if k and k not in _PLACEHOLDERS and k != current])


def ready() -> bool:
    """True when there is a real key to encrypt with."""
    return bool(_masters())


def _derive(master: str, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"portfolio-cms-vault-v1", info=purpose).derive(master.encode())


@lru_cache(maxsize=8)
def _fernet(masters: tuple) -> MultiFernet:
    return MultiFernet([Fernet(base64.urlsafe_b64encode(_derive(m, b"encrypt"))) for m in masters])


@lru_cache(maxsize=32)
def _blind_key(master: str, purpose: str) -> bytes:
    return _derive(master, b"blind:" + purpose.encode())


def encrypt(text: str) -> str:
    masters = _masters()
    if not masters:
        raise RuntimeError("No encryption key is set (MESSAGE_ENCRYPTION_KEY or SECRET_KEY).")
    return _PREFIX + _fernet(masters).encrypt((text or "").encode()).decode()


def decrypt(token: str):
    """The original text, or None if the token is missing, damaged or was made with a key we don't have."""
    masters = _masters()
    if not masters or not token or not token.startswith(_PREFIX):
        return None
    try:
        return _fernet(masters).decrypt(token[len(_PREFIX):].encode()).decode()
    except (InvalidToken, ValueError):
        return None


def blind(purpose: str, value: str) -> str:
    """A keyed one-way code for `value`. The same value and purpose always give the same code."""
    masters = _masters()
    if not masters:
        raise RuntimeError("No encryption key is set (MESSAGE_ENCRYPTION_KEY or SECRET_KEY).")
    return hmac.new(_blind_key(masters[0], purpose), (value or "").encode(), hashlib.sha256).hexdigest()
