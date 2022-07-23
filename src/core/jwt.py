import jwt
import uuid

from datetime import datetime, timedelta

from src.core.config import (JWT_ALGORITHM, JWT_SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES)


def create_access_token(*, data: dict, refresh_jti: str, expires_delta: timedelta = None):
    jti = str(uuid.uuid4())
    to_encode = data.copy()
    time_now = datetime.utcnow()
    to_encode.update({"iat": int(time_now.timestamp()), "jti": jti, "nbf": int(time_now.timestamp()), "refresh_jti": refresh_jti})
    if expires_delta:
        expire = time_now + expires_delta
    else:
        expire = time_now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp()), "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(*, user_uuid: str):
    time_now = datetime.utcnow()
    time_delta = timedelta(days=30)
    jti = str(uuid.uuid4())
    expire = time_now + time_delta
    to_encode = {"iat": int(time_now.timestamp()), "jti": jti, "type": "refresh", "uuid": user_uuid, "nbf": int(time_now.timestamp()), "exp": int(expire.timestamp())}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, JWT_ALGORITHM)
    return encoded_jwt
