import uuid as uuid_pkg

from datetime import datetime

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("username"), UniqueConstraint("email"))
    uuid: uuid_pkg.UUID = Field(default_factory=uuid_pkg.uuid4, primary_key=True, index=True, nullable=False)
    username: str = Field(nullable=False, max_length=20)
    email: str = Field(nullable=False, max_length=25)
    hashed_password: str = Field(nullable=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    is_superuser: bool = Field(default=False, nullable=False)
