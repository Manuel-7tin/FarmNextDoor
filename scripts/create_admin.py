import getpass
import sys

from sqlalchemy import select

from app.database import SessionLocal
from app.models import User
from app.security import hash_password
from app.routers.auth import validate_password


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: "
            "python scripts/create_admin.py admin@example.com"
        )
        sys.exit(1)

    email = sys.argv[1].strip().lower()

    password = getpass.getpass(
        "Admin password: "
    )

    confirm = getpass.getpass(
        "Confirm password: "
    )

    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    try:
        validate_password(password)
    except Exception as exc:
        print(exc.detail)
        sys.exit(1)

    db = SessionLocal()

    try:
        user = db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if user:
            user.role = "admin"
            user.is_email_verified = True
            user.is_active = True
            user.password_hash = hash_password(
                password
            )

            db.commit()

            print(
                f"Updated {email} as admin."
            )

            return

        user = User(
            email=email,
            password_hash=hash_password(
                password
            ),
            role="admin",
            is_active=True,
            is_email_verified=True,
        )

        db.add(user)
        db.commit()

        print(
            f"Created admin: {email}"
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()