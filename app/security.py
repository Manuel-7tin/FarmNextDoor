import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from pwdlib import PasswordHash

from .config import get_settings


settings = get_settings()

password_hash = PasswordHash.recommended()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        password,
        hashed_password,
    )


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_compare(
    first: str,
    second: str,
) -> bool:
    return secrets.compare_digest(
        first,
        second,
    )


def session_expiry(
    remember_me: bool,
) -> datetime:
    if remember_me:
        return utc_now() + timedelta(
            days=settings.remember_me_days
        )

    return utc_now() + timedelta(
        hours=settings.session_expire_hours
    )


def verification_expiry() -> datetime:
    return utc_now() + timedelta(
        hours=settings.email_verification_hours
    )


def reset_expiry() -> datetime:
    return utc_now() + timedelta(
        minutes=settings.password_reset_minutes
    )