from datetime import timedelta

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..dependencies import (
    get_current_session,
    get_current_user,
    require_csrf,
)
from ..email_service import (
    send_password_reset_email,
    send_verification_email,
)
from ..models import (
    EmailVerificationToken,
    PasswordResetToken,
    RateLimit,
    User,
    UserSession,
)
from ..schemas import (
    CSRFResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    UserResponse,
)
from ..security import (
    generate_csrf_token,
    generate_token,
    hash_password,
    hash_token,
    reset_expiry,
    session_expiry,
    utc_now,
    verification_expiry,
    verify_password,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

settings = get_settings()


def get_client_ip(
    request: Request,
) -> str:

    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def set_session_cookie(
    response: Response,
    token: str,
    remember_me: bool,
) -> None:

    if remember_me:
        max_age = (
            settings.remember_me_days
            * 24
            * 60
            * 60
        )
    else:
        max_age = (
            settings.session_expire_hours
            * 60
            * 60
        )

    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain or None,
        path="/",
    )


def delete_session_cookie(
    response: Response,
) -> None:

    response.delete_cookie(
        key=settings.cookie_name,
        domain=settings.cookie_domain or None,
        path="/",
    )


def validate_password(
    password: str,
) -> None:

    if len(password) < settings.min_password_length:
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must be at least "
                f"{settings.min_password_length} characters"
            ),
        )

    if len(password) > settings.max_password_length:
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must not exceed "
                f"{settings.max_password_length} characters"
            ),
        )

    if not any(
        char.isupper()
        for char in password
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must contain "
                "at least one uppercase letter"
            ),
        )

    if not any(
        char.islower()
        for char in password
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must contain "
                "at least one lowercase letter"
            ),
        )

    if not any(
        char.isdigit()
        for char in password
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must contain "
                "at least one number"
            ),
        )


def check_ip_rate_limit(
    db: Session,
    request: Request,
) -> None:

    key = f"login-ip:{get_client_ip(request)}"
    now = utc_now()

    limit = db.get(
        RateLimit,
        key,
    )

    if not limit:
        db.add(
            RateLimit(
                key=key,
                window_started_at=now,
                attempts=1,
            )
        )

        db.commit()
        return

    window = timedelta(
        minutes=settings.ip_rate_limit_window_minutes
    )

    if now - limit.window_started_at >= window:
        limit.window_started_at = now
        limit.attempts = 1

        db.commit()
        return

    if (
        limit.attempts
        >= settings.ip_rate_limit_attempts
    ):
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many login attempts. "
                "Please try again later."
            ),
        )

    limit.attempts += 1

    db.commit()


@router.get(
    "/csrf",
    response_model=CSRFResponse,
)
def get_csrf_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Bootstrap an anonymous browser session.

    The frontend calls this before register/login.
    """

    raw_token = request.cookies.get(
        settings.cookie_name
    )

    session = None

    if raw_token:
        session = db.scalar(
            select(UserSession).where(
                UserSession.session_token_hash
                == hash_token(raw_token)
            )
        )

    if not session:
        raw_token = generate_token()

        session = UserSession(
            user_id=None,
            session_token_hash=hash_token(
                raw_token
            ),
            csrf_token=generate_csrf_token(),
            expires_at=session_expiry(False),
        )

        db.add(session)
        db.commit()

        set_session_cookie(
            response,
            raw_token,
            False,
        )

    return CSRFResponse(
        csrf_token=session.csrf_token
    )


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    session: UserSession = Depends(
        get_current_session
    ),
    csrf_session: UserSession = Depends(
        require_csrf
    ),
    db: Session = Depends(get_db),
):

    email = str(payload.email).lower().strip()

    existing = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        )

    validate_password(
        payload.password
    )

    user = User(
        email=email,
        password_hash=hash_password(
            payload.password
        ),
        role="customer",
        is_active=True,
        is_email_verified=False,
    )

    db.add(user)
    db.flush()

    raw_token = generate_token()

    verification = EmailVerificationToken(
        user_id=user.id,
        token_hash=hash_token(
            raw_token
        ),
        expires_at=verification_expiry(),
    )

    db.add(verification)

    db.commit()

    background_tasks.add_task(
        send_verification_email,
        user.email,
        raw_token,
    )

    return MessageResponse(
        message=(
            "Registration successful. "
            "Please check your email to verify your account."
        )
    )


@router.post(
    "/login",
    response_model=LoginResponse,
)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    session: UserSession = Depends(
        get_current_session
    ),
    csrf_session: UserSession = Depends(
        require_csrf
    ),
):

    check_ip_rate_limit(
        db,
        request,
    )

    email = str(payload.email).lower().strip()

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    generic_error = (
        "Invalid email or password"
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail=generic_error,
        )

    now = utc_now()

    if (
        user.locked_until
        and user.locked_until > now
    ):
        raise HTTPException(
            status_code=423,
            detail=(
                "Account temporarily locked. "
                "Please try again later."
            ),
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        user.failed_login_attempts += 1

        if (
            user.failed_login_attempts
            >= settings.max_login_failures
        ):
            user.locked_until = (
                now
                + timedelta(
                    minutes=settings.lockout_minutes
                )
            )

            user.failed_login_attempts = 0

        db.commit()

        raise HTTPException(
            status_code=401,
            detail=generic_error,
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is disabled",
        )

    if not user.is_email_verified:
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in",
        )

    user.failed_login_attempts = 0
    user.locked_until = None

    # Rotate the anonymous session into an authenticated one.
    db.delete(session)

    raw_session_token = generate_token()

    new_session = UserSession(
        user_id=user.id,
        session_token_hash=hash_token(
            raw_session_token
        ),
        csrf_token=generate_csrf_token(),
        expires_at=session_expiry(
            payload.remember_me
        ),
    )

    db.add(new_session)
    db.commit()

    set_session_cookie(
        response,
        raw_session_token,
        payload.remember_me,
    )

    return LoginResponse(
        message="Login successful",
        user=UserResponse.model_validate(
            user
        ),
        csrf_token=new_session.csrf_token,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
)
def logout(
    response: Response,
    session: UserSession = Depends(
        require_csrf
    ),
    db: Session = Depends(get_db),
):

    db.delete(session)
    db.commit()

    delete_session_cookie(response)

    return MessageResponse(
        message="Logged out successfully"
    )


@router.get(
    "/me",
    response_model=LoginResponse,
)
def me(
    session: UserSession = Depends(
        get_current_session
    ),
    user: User = Depends(
        get_current_user
    ),
):

    return LoginResponse(
        message="Authenticated",
        user=UserResponse.model_validate(
            user
        ),
        csrf_token=session.csrf_token,
    )


@router.post(
    "/verify-email",
    response_model=MessageResponse,
)
def verify_email(
    token: str,
    db: Session = Depends(get_db),
):

    record = db.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash
            == hash_token(token)
        )
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid verification token",
        )

    if record.used_at:
        raise HTTPException(
            status_code=400,
            detail="Verification token has already been used",
        )

    if record.expires_at <= utc_now():
        raise HTTPException(
            status_code=400,
            detail="Verification token has expired",
        )

    user = db.get(
        User,
        record.user_id,
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    user.is_email_verified = True
    record.used_at = utc_now()

    db.commit()

    return MessageResponse(
        message="Email verified successfully"
    )


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
)
def resend_verification(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):

    email = str(payload.email).lower().strip()

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    # Intentionally generic to prevent
    # account enumeration.
    if (
        user
        and user.is_active
        and not user.is_email_verified
    ):
        db.execute(
            delete(
                EmailVerificationToken
            ).where(
                EmailVerificationToken.user_id
                == user.id
            )
        )

        raw_token = generate_token()

        record = EmailVerificationToken(
            user_id=user.id,
            token_hash=hash_token(
                raw_token
            ),
            expires_at=verification_expiry(),
        )

        db.add(record)
        db.commit()

        background_tasks.add_task(
            send_verification_email,
            user.email,
            raw_token,
        )

    return MessageResponse(
        message=(
            "If the account exists and "
            "requires verification, "
            "a new verification email has been sent."
        )
    )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
)
def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):

    email = str(payload.email).lower().strip()

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if user and user.is_active:

        db.execute(
            delete(
                PasswordResetToken
            ).where(
                PasswordResetToken.user_id
                == user.id
            )
        )

        raw_token = generate_token()

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(
                raw_token
            ),
            expires_at=reset_expiry(),
        )

        db.add(reset_record)
        db.commit()

        background_tasks.add_task(
            send_password_reset_email,
            user.email,
            raw_token,
        )

    return MessageResponse(
        message=(
            "If an account exists for that email, "
            "a password reset email has been sent."
        )
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
)
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):

    record = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash
            == hash_token(payload.token)
        )
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    if record.used_at:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    if record.expires_at <= utc_now():
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    validate_password(
        payload.password
    )

    user = db.get(
        User,
        record.user_id,
    )

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    user.password_hash = hash_password(
        payload.password
    )

    user.failed_login_attempts = 0
    user.locked_until = None

    record.used_at = utc_now()

    # Resetting the password logs
    # the user out everywhere.
    db.execute(
        delete(UserSession).where(
            UserSession.user_id == user.id
        )
    )

    db.commit()

    return MessageResponse(
        message=(
            "Password reset successfully. "
            "Please log in again."
        )
    )


@router.post(
    "/change-password",
    response_model=MessageResponse,
)
def change_password(
    payload: ChangePasswordRequest,
    session: UserSession = Depends(
        require_csrf
    ),
    user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):

    if not verify_password(
        payload.current_password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect",
        )

    validate_password(
        payload.new_password
    )

    if (
        payload.current_password
        == payload.new_password
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "New password must be "
                "different from the current password"
            ),
        )

    user.password_hash = hash_password(
        payload.new_password
    )

    # Invalidate all sessions.
    db.execute(
        delete(UserSession).where(
            UserSession.user_id == user.id
        )
    )

    db.commit()

    return MessageResponse(
        message=(
            "Password changed successfully. "
            "Please log in again."
        )
    )
