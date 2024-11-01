from typing import Annotated
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext

from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status

from jose import jwt, JWTError, ExpiredSignatureError

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db_depends import get_db
from .config import SECRET_KEY, ALGORITHM
from .redis_depends import redis
from app.models.users import User


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


async def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def create_refresh_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'type': 'refresh'}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def create_tokens(username: str, user_id: int, access_expires: timedelta, refresh_expires: timedelta):
    access_token = await create_access_token(username, user_id, expires_delta=access_expires)
    refresh_token = await create_refresh_token(username, user_id, expires_delta=refresh_expires)
    await redis.set(f"refresh_token:{user_id}", refresh_token, ex=int(refresh_expires.total_seconds()))
    return access_token, refresh_token

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        expire = payload.get('exp')

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Could not validate user'
            )

        if expire is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No access token supplied"
            )
        return {
            'username': username,
            'user_id': user_id
        }

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired!"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='JWTError. Could not validate user'
        )

async def authenticate_user(db: Annotated[AsyncSession, Depends(get_db)], username: str, password_hash: str):
    user = await db.scalar(select(User).where(User.username == username))
    if not user or not bcrypt_context.verify(password_hash, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
