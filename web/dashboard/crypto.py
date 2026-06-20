# web/dashboard/crypto.py
"""Encryption for the API credential vault.

Keys are stored Fernet-encrypted. The Fernet key comes from RENGINE_VAULT_KEY
when set (so rotating Django's SECRET_KEY does not invalidate the vault), else it
is derived from SECRET_KEY via HKDF — with a one-time warning recommending the
dedicated env var for production.
"""
import base64
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

logger = logging.getLogger(__name__)

_fernet = None
_warned = False


def _derive_from_secret_key():
    global _warned
    if not _warned:
        logger.warning(
            'RENGINE_VAULT_KEY is not set; deriving the API-vault key from '
            'SECRET_KEY. Set RENGINE_VAULT_KEY in production so rotating '
            'SECRET_KEY does not invalidate stored credentials.')
        _warned = True
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b'rengine-api-vault').derive(settings.SECRET_KEY.encode())
    return base64.urlsafe_b64encode(raw)


def _get_fernet():
    global _fernet
    if _fernet is None:
        env_key = os.environ.get('RENGINE_VAULT_KEY')
        key = env_key.encode() if env_key else _derive_from_secret_key()
        _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str):
    if not token:
        return None
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        logger.warning('API-vault decrypt failed for a stored credential (skipping).')
        return None
