from typing import Annotated
from datetime import timedelta

from jose import jwt, JWTError, ExpiredSignatureError

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app.models.users import User
from app.schemas.schemas import CreateUser
from app.backend.db_depends import get_db
from app.backend.config import SECRET_KEY, ALGORITHM
from app.backend.redis_depends import redis
from app.backend.tokens import bcrypt_context, authenticate_user, create_tokens, create_access_token, oauth2_scheme


router = APIRouter(prefix='/auth', tags=['auth'])


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

@router.post('/login')
async def login(db: Annotated[AsyncSession, Depends(get_db)], form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authenticate_user(db, form_data.username, form_data.password)
    access_token, refresh_token = await create_tokens(user.username, user.id, access_expires=timedelta(minutes=20), refresh_expires=timedelta(days=30))

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer'
    }

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
