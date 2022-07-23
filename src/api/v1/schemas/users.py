import re
import uuid as uuid_pkg

from datetime import datetime

from pydantic import BaseModel, Field, validator

__all__ = ("Token", "UserLogin", "UserModel", "UserCreate", "UserUpdate")


class Token(BaseModel):
    access_token: str
    refresh_token: str


class UserBase(BaseModel):
    username: str = Field(min_length=4, max_length=20)


class UserLogin(BaseModel):
    username: str
    password: str


class UserCreate(UserBase):
    password: str = Field(min_length=4, max_length=30)
    email: str = Field(min_length=6, max_length=25)

    @validator("email")
    def check_email(cls, v):
        pattern = r"^[-\w\.]+@([-\w]+\.)+[-\w]{2,4}$"
        if not re.match(pattern, v):
            raise ValueError('Неправильный адрес электронной почты.')
        return v


class UserModel(UserBase):
    uuid: uuid_pkg.UUID
    email: str
    created_at: datetime
    is_superuser: bool
    is_active: bool


class UserUpdate(BaseModel):
    username: str = Field(default=None, min_length=4, max_length=20)
    email: str = Field(default=None, min_length=6, max_length=25)

    @validator("email")
    def check_email(cls, v):
        pattern = r"^[-\w\.]+@([-\w]+\.)+[-\w]{2,4}$"
        if v is None:
            return v
        if not re.match(pattern, v):
            raise ValueError('Неправильный адрес электронной почты.')
        return v
