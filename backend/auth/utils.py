from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr, validator
from fastapi import APIRouter, HTTPException, Body
from starlette import status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os

load_dotenv()

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = 'HS256'


class CreateUserRequest(BaseModel):
    firstName: str
    lastName: str
    country: str
    email: EmailStr
    password: str

    @validator("password")
    def validate_password(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit")
        
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")
        
        if not any(char.islower() for char in password):
            raise ValueError("Password must contain at least one lowercase letter")
        
        return password

class Token(BaseModel):
    access_token: str
    token_type: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify the provided password against the hashed password.
    """
    return bcrypt_context.verify(plain_password, hashed_password)


def create_access_token(username: str, user_id: str, expires_delta: timedelta = None):
    """
    Generate an access token with a short expiry time.
    """
    print("secret_key : ", SECRET_KEY)
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))))
    payload = {"sub": username, "id": user_id, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str, user_id: str, expires_delta: timedelta = None):
    """
    Generate a refresh token with a long expiry time.
    """
    print("secret_key : ", SECRET_KEY)
    expire = datetime.utcnow() + (expires_delta or timedelta(days=int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS'))))
    payload = {"sub": username, "id": user_id, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

