from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import (
    get_current_user,
    require_admin,
)
from ..models import User
from ..schemas import UserResponse


router = APIRouter(
    prefix="/api/v1/users",
    tags=["Users"],
)


@router.get(
    "/me",
    response_model=UserResponse,
)
def get_my_profile(
    user: User = Depends(
        get_current_user
    ),
):
    return UserResponse.model_validate(
        user
    )


@router.get(
    "",
    response_model=list[UserResponse],
)
def list_users(
    admin: User = Depends(
        require_admin
    ),
    db: Session = Depends(get_db),
):
    users = db.scalars(
        select(User)
        .order_by(User.created_at.desc())
    ).all()

    return [
        UserResponse.model_validate(user)
        for user in users
    ]