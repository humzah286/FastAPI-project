from jose import jwt
from fastapi import APIRouter, HTTPException, Body
from starlette import status
from pymongo.errors import DuplicateKeyError
from database import get_db
from .utils import *

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

mongoClient = get_db()


@router.post('/register', status_code=status.HTTP_201_CREATED)
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
    
    
    access_token = create_access_token(user["email"], str(user["_id"]))
    refresh_token = create_refresh_token(user["email"], str(user["_id"]))
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post('/login', status_code=status.HTTP_200_OK)
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
    
    access_token = create_access_token(user["email"], str(user["_id"]))
    refresh_token = create_refresh_token(user["email"], str(user["_id"]))
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }




@router.post("/refresh", response_model=Token, status_code=status.HTTP_200_OK)
def refresh_access_token(refresh_token: str = Body(..., embed=True)):
    """
    Verify the refresh token and generate a new access token.
    """

    try:
        print("refresh_token : ", refresh_token)
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("id")

        if not username or not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_access_token = create_access_token(username, user_id)

        return {"access_token": new_access_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


