from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Optional

import os

# Basic app setup

app = FastAPI(
    title="Mini Insta API",
    description="A tiny social network backend demo with basic login.",
    version="0.1.0",
)

load_dotenv(override=True)

# reading values from the .env file
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

# password hashing setup
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.get("/", include_in_schema=False)
def serve_frontend():
    """
    Returns the main index.html file for the small frontend.
    This just serves the static file and doesn't do anything else.
    """
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


# Pydantic models

class User(BaseModel):
    """Basic user model used for responses."""
    username: str
    full_name: Optional[str] = None


class UserInDB(User):
    """Internal user model that includes the stored hashed password."""
    hashed_password: str


class Token(BaseModel):
    """Model for the JWT token returned after login."""
    access_token: str
    token_type: str = "bearer"


# database users

fake_users_db = {}


def get_password_hash(password: str) -> str:
    """
    Takes a plain password and returns a hashed version of it.
    Uses passlib under the hood.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compares a plain password with the hashed version.
    Returns True if they match.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str) -> Optional[UserInDB]:
    """
    Looks up a user in the fake in-memory database.
    Returns the user model or None if not found.
    """
    user = fake_users_db.get(username)
    if user:
        return UserInDB(**user)
    return None


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """
    Checks if a user exists and if the password is correct.
    Returns the user object if authentication succeeds.
    """
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT access token with an expiration time.

    Args:
        data: The payload to encode inside the token (e.g., {"sub": username}).
        expires_delta: Optional timedelta for the token expiry.

    Returns:
        Encoded JWT token as a string.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    expire = now + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Auth routes

@app.post("/auth/register", response_model=User)
def register_user(user: User, password: str):
    """
    Registers a new user in the fake database.

    Note:
        Password comes as a separate query parameter for simplicity.
    """
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_pw = get_password_hash(password)

    fake_users_db[user.username] = {
        "username": user.username,
        "full_name": user.full_name,
        "hashed_password": hashed_pw,
    }

    return user


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Logs the user in using form data.
    If valid, returns a JWT token.
    """
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )

    return Token(access_token=token)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Validates the provided JWT token and loads the associated user.

    Returns:
        User model if token is valid.

    Raises:
        HTTPException if token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user(username)
    if user is None:
        raise credentials_exception

    return User(username=user.username, full_name=user.full_name)


@app.get("/me", response_model=User)
async def read_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently logged-in user.
    Requires the Authorization: Bearer <token> header.
    """
    return current_user
