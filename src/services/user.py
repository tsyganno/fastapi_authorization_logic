import jwt
from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException
from jwt import PyJWTError
from sqlmodel import Session, select
from starlette.status import HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED

from src.api.v1.schemas import UserCreate, UserModel
from src.api.v1.schemas.users import UserUpdate
from src.core.config import JWT_SECRET_KEY, JWT_ALGORITHM
from src.core.security import verify_password, get_password_hash
from src.db import (AbstractCache,
                    CacheRefreshTkns,
                    get_cache,
                    get_session,
                    get_access_cash,
                    get_refresh_cash)
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def __init__(self,
                 cache: AbstractCache,
                 access_cash: AbstractCache,
                 refresh_cash: CacheRefreshTkns,
                 session: Session):
        super().__init__(cache=cache, session=session)

        self.blocked_access_tokens = access_cash
        self.active_refresh_tokens = refresh_cash

    def get_by_username(self, username: str) -> Optional[User]:
        """Gets user by username from database"""
        return self.session.query(User).filter(User.username == username).first()

    def get_by_uuid(self, uuid: str) -> Optional[User]:
        """Gets user by uuid from database"""
        return self.session.query(User).filter(User.uuid == uuid).first()

    def create_user(self, user: UserCreate) -> dict:
        """Creates user"""
        password_hash = get_password_hash(user.password)
        print(f'---\nusername={user.username}\nemail={user.email}\npass={password_hash}\n---')
        new_user = User(
            username=user.username,
            hashed_password=password_hash,
            email=user.email
        )
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Performs authentication"""
        user = self.get_by_username(username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def get_current_user(self, token: str):
        """Gets current user from database"""
        jti = self.get_jti(token)
        if self.check_block_token(jti):
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Token was blocked"
            )

        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_data = UserModel(**payload)
        except PyJWTError:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
            )
        user = self.session.query(User).filter(User.username == user_data.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.dict()

    def update_user(self, user: dict, new_data: UserUpdate) -> dict:
        """Updates user in database"""
        statement = select(User).where(User.username == user["username"])
        results = self.session.exec(statement)
        selected_user = results.one()
        if new_data.username is not None:
            selected_user.username = new_data.username
        if new_data.email is not None:
            selected_user.email = new_data.email

        self.session.add(selected_user)
        self.session.commit()
        self.session.refresh(selected_user)

        return selected_user.dict()

    def check_block_token(self, jti: str) -> bool:
        """Checks the token among the blocked ones"""
        if self.blocked_access_tokens.get(jti):
            return True
        return False

    def block_access_token(self, jti: str) -> None:
        """Blocks the token"""
        self.blocked_access_tokens.set(jti, "blocked")

    def add_refresh_token(self, token: str):
        """Adds a refresh token to the active list"""
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload["jti"]
        uuid = payload["uuid"]
        self.active_refresh_tokens.add(uuid, jti)

    def remove_refresh_token(self, uuid: str, jti: str) -> None:
        """Removes a refresh token to the active list"""
        current_tokens = self.active_refresh_tokens.get(uuid)
        current_tokens.pop(current_tokens.index(jti))
        self.active_refresh_tokens.clean(uuid)
        if current_tokens:
            self.active_refresh_tokens.add(uuid, *current_tokens)

    def remove_all_refresh_tokens(self, uuid: str) -> None:
        """Clears the list of active tokens"""
        self.active_refresh_tokens.clean(uuid)

    def check_refresh_token(self, uuid: str, jti: str) -> bool:
        """Checks the refresh token in the active list"""
        current_tokens = self.active_refresh_tokens.get(uuid)
        return True if jti in current_tokens else False

    @staticmethod
    def get_jti(token: str) -> str:
        """Gets jti from token"""
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload["jti"]
        return jti


@lru_cache()
def get_user_service(
        cache: AbstractCache = Depends(get_cache),
        access_cash: AbstractCache = Depends(get_access_cash),
        refresh_cash: CacheRefreshTkns = Depends(get_refresh_cash),
        session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache,
                       access_cash=access_cash,
                       refresh_cash=refresh_cash,
                       session=session)
