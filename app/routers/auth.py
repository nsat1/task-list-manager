from typing import Annotated
from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError, ExpiredSignatureError

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert, select

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from passlib.context import CryptContext

from app.models.users import User
from app.schemas.schemas import CreateUser
from app.backend.db_depends import get_db
from app.backend.config import SECRET_KEY, ALGORITHM
from app.backend.redis_depends import redis


router = APIRouter(prefix='/auth', tags=['auth'])
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(db: Annotated[AsyncSession, Depends(get_db)], create_user: CreateUser):
    await db.execute(insert(User).values(
        username=create_user.username,
        password_hash=bcrypt_context.hash(create_user.password_hash),
    ))
    await db.commit()

    return {
        'status_code': status.HTTP_201_CREATED,
        'transaction': 'Successful'
    }

async def authenticate_user(db: Annotated[AsyncSession, Depends(get_db)], username: str, password_hash: str):
    user = await db.scalar(select(User).where(User.username == username))
    if not user or not bcrypt_context.verify(password_hash, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

@router.post('/login')
async def login(db: Annotated[AsyncSession, Depends(get_db)], form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authenticate_user(db, form_data.username, form_data.password)
    access_token, refresh_token = await create_tokens(user.username, user.id, access_expires=timedelta(minutes=20), refresh_expires=timedelta(days=30))

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer'
    }

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


@router.post('/refresh')
async def refresh_token(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get('id')
        token_type = payload.get('type')

        if token_type != 'refresh':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        stored_refresh_token = await redis.get(f"refresh_token:{user_id}")
        if not stored_refresh_token or stored_refresh_token.decode() != token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        access_token = await create_access_token(payload.get('sub'), user_id, expires_delta=timedelta(minutes=20))

        return {
            'access_token': access_token,
            'token_type': 'bearer'
        }

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )