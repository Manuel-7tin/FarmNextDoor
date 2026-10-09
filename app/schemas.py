#This is the API contract your frontend developer will work against.

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)


class MessageResponse(BaseModel):
    message: str


class CSRFResponse(BaseModel):
    csrf_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: int
    email: EmailStr
    role: str
    is_active: bool
    is_email_verified: bool
    created_at: datetime


class RegisterRequest(BaseModel):
    first_name: str = Field(
        min_length=1,
        max_length=100,
    )

    last_name: str = Field(
        min_length=1,
        max_length=100,
    )
    email: EmailStr
    phone: str = Field(
        min_length=7,
        max_length=20,
    )

    i_am: Literal["customer", "farmer"]
    password: str = Field(
        min_length=8,
        max_length=128,
    )
    confirm_password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("first_name", "last_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Name cannot be empty")

        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr):
        return str(value).strip().lower()

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Phone number cannot be empty")

        return value

    @field_validator("confirm_password")
    @classmethod
    def passwords_must_match(
        cls,
        value,
        info,
    ):
        password = info.data.get("password")

        if password and value != password:
            raise ValueError(
                "Passwords do not match"
            )

        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=128,
    )
    remember_me: bool = False

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr):
        return str(value).strip().lower()


class LoginResponse(BaseModel):
    message: str
    user: UserResponse
    csrf_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr):
        return str(value).strip().lower()


class ResetPasswordRequest(BaseModel):
    token: str = Field(
        min_length=20,
        max_length=200,
    )

    password: str = Field(
        min_length=8,
        max_length=128,
    )

    confirm_password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("confirm_password")
    @classmethod
    def passwords_must_match(
        cls,
        value,
        info,
    ):
        password = info.data.get("password")

        if password and value != password:
            raise ValueError(
                "Passwords do not match"
            )

        return value


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(
        min_length=1,
        max_length=128,
    )

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )

    confirm_password: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("confirm_password")
    @classmethod
    def passwords_must_match(
        cls,
        value,
        info,
    ):
        password = info.data.get("new_password")

        if password and value != password:
            raise ValueError(
                "Passwords do not match"
            )

        return value