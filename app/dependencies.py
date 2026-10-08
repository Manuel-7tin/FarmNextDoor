from datetime import datetime, timezone

from fastapi import (
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import User, UserSession
from .security import (
    constant_time_compare,
    hash_token,
)


settings = get_settings()


def get_session_from_request(
    request: Request,
    db: Session,
) -> UserSession:

    raw_token = request.cookies.get(
        settings.cookie_name
    )

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session = db.scalar(
        select(UserSession).where(
            UserSession.session_token_hash
            == hash_token(raw_token)
        )
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if session.expires_at <= datetime.now(
        timezone.utc
    ):
        db.delete(session)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    return session


def get_current_session(
    request: Request,
    db: Session = Depends(get_db),
) -> UserSession:

    return get_session_from_request(
        request,
        db,
    )


def get_current_user(
    session: UserSession = Depends(
        get_current_session
    ),
    db: Session = Depends(get_db),
) -> User:

    if session.user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = db.get(
        User,
        session.user_id,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


def require_admin(
    user: User = Depends(get_current_user),
) -> User:

    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return user


def require_csrf(
    csrf_token: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
    session: UserSession = Depends(
        get_current_session
    ),
) -> UserSession:

    if not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token required",
        )

    if not constant_time_compare(
        session.csrf_token,
        csrf_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )

    return session