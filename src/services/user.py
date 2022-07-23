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
from src.db import (AbstractCache, CacheRefreshTkns, get_cache, get_session, get_access_cash, get_refresh_cash)
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def __init__(self, cache: AbstractCache, access_cash: AbstractCache, refresh_cash: CacheRefreshTkns,
                 session: Session):
        super().__init__(cache=cache, session=session)
        self.blocked_access_tokens = access_cash
        self.active_refresh_tokens = refresh_cash

    def get_by_username(self, username: str) -> Optional[User]:
        """Получение пользователя по имени пользователя из базы данных"""
        return self.session.query(User).filter(User.username == username).first()

    def get_by_uuid(self, uuid: str) -> Optional[User]:
        """Получение пользователя по uuid из базы данных"""
        return self.session.query(User).filter(User.uuid == uuid).first()

    def create_user(self, user: UserCreate) -> dict:
        """Создание пользователя"""
        password_hash = get_password_hash(user.password)
        new_user = User(username=user.username, hashed_password=password_hash, email=user.email)
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Выполнение аутентификации"""
        user = self.get_by_username(username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def get_current_user(self, token: str):
        """Получение текущего пользователя из базы данных"""
        jti = self.get_jti(token)
        if self.check_block_token(jti):
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Токен был заблокирован.")
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_data = UserModel(**payload)
        except PyJWTError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Не удалось проверить учетные данные.")
        user = self.session.query(User).filter(User.username == user_data.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден.")
        return user.dict()

    def update_user(self, user: dict, new_data: UserUpdate) -> dict:
        """Обновление пользователя в базе"""
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
        """Проверка токена среди заблокированных"""
        if self.blocked_access_tokens.get(jti):
            return True
        return False

    def block_access_token(self, jti: str) -> None:
        """Блокировка токена"""
        self.blocked_access_tokens.set(jti, "blocked")

    def add_refresh_token(self, token: str):
        """Добавление токена обновления в активный список"""
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload["jti"]
        uuid = payload["uuid"]
        self.active_refresh_tokens.add(uuid, jti)

    def remove_refresh_token(self, uuid: str, jti: str) -> None:
        """Удаление токена обновления в активный список"""
        current_tokens = self.active_refresh_tokens.get(uuid)
        current_tokens.pop(current_tokens.index(jti))
        self.active_refresh_tokens.clean(uuid)
        if current_tokens:
            self.active_refresh_tokens.add(uuid, *current_tokens)

    def remove_all_refresh_tokens(self, uuid: str) -> None:
        """Очищение списка активных токенов"""
        self.active_refresh_tokens.clean(uuid)

    def check_refresh_token(self, uuid: str, jti: str) -> bool:
        """Проверка токена обновления в активном списке"""
        current_tokens = self.active_refresh_tokens.get(uuid)
        return True if jti in current_tokens else False

    @staticmethod
    def get_jti(token: str) -> str:
        """Получение jti из токена"""
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
    return UserService(cache=cache, access_cash=access_cash, refresh_cash=refresh_cash, session=session)
