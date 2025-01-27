from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, HTTPException, Body
from starlette import status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated
from pymongo.errors import DuplicateKeyError
from database import get_db
import os

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

mongoClient = get_db()

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

    collection = mongoClient["mydatabase"]["users"]
    print(create_user_request)

    user = {
        "firstName":create_user_request.firstName,
        "lastName": create_user_request.lastName,
        "email":create_user_request.email,
        "password":bcrypt_context.hash(create_user_request.password),
        "country": create_user_request.country,
    }
    try:
        result = collection.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(
            status_code=400, detail="A user with this email already exists"
        )
    print("done: ", result)
    return {"id": str(result.inserted_id), "email": user["email"], "firstName": user['firstName']}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify the provided password against the hashed password.
    """
    return bcrypt_context.verify(plain_password, hashed_password)


@router.post('/verify_user', status_code=status.HTTP_200_OK)
def get_user_by_email_and_password(email: str = Body(...), password: str = Body(...)):
    """
    Get the user based on email and verify the password.
    """

    collection = mongoClient["mydatabase"]["users"]
    print("finding user with email : ", email)
    user = collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    return {
        "id": str(user["_id"]),
        "firstName": user["firstName"],
        "lastName": user["lastName"],
        "email": user["email"],
        "country": user["country"]
    }


