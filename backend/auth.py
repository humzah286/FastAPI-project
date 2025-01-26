from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter
from starlette import status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated
from main import app
import os

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)


SECRET_KEY = os.getenv('SECRET_KEY')
ALOGORITHM = 'HS256'


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class CreateUserRequest(BaseModel):
    firstName: str
    lastName: str
    country: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str



@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest):

    collection = app.mongodb["users"]
    print(create_user_request)
    create_user_request = create_user_request.dict()

    user = {
        "firstName":create_user_request.firstName,
        "lastName": create_user_request.lastName,
        "email":create_user_request.email,
        "password":bcrypt_context.hash(create_user_request.password),
        "country": create_user_request.country,
    }

    result = collection.insert_one(user)
    print("done: ", result)
    return {"id": str(result.inserted_id), "email": user["email"], "firstName": user['firstName']}

