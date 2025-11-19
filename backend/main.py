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

from .db import init_db, get_user_row, insert_user_row

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

# Paths

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

# make sure the DB + table exist before we start handling requests
init_db()


@app.get("/", include_in_schema=False)
def serve_frontend():
    """
    Returns the main index.html file for the small frontend.
    This just serves the static file and doesn't do anything else.
    """
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


# Pydantic models

class User(BaseModel):
    """
    Basic user profile returned by the API.
    Kept simple on purpose, but slightly closer to a real account.
    """
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    bio: Optional[str] = None
    dob: Optional[str] = None  # e.g. "2001-05-10"


class UserInDB(User):
    """
    Internal user model that includes the stored hashed password.
    This is what we actually keep in the database.
    """
    hashed_password: str


class Token(BaseModel):
    """Model for the JWT token returned after login."""
    access_token: str
    token_type: str = "bearer"


# Password + user helpers (using db.py underneath)

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
    Fetch a user from the DB and convert the row into a UserInDB object.
    """
    row = get_user_row(username)
    if not row:
        return None

    return UserInDB(
        username=row["username"],
        full_name=row["full_name"],
        email=row["email"],
        bio=row["bio"],
        dob=row["dob"],
        hashed_password=row["hashed_password"],
    )


def create_user(user: User, hashed_password: str) -> UserInDB:
    """
    Create a new user in the DB from the public User model + hashed password.
    """
    insert_user_row(
        {
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "bio": user.bio,
            "dob": user.dob,
            "hashed_password": hashed_password,
        }
    )

    return UserInDB(
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        bio=user.bio,
        dob=user.dob,
        hashed_password=hashed_password,
    )


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
    Registers a new user in the database.

    Note:
        Password comes as a separate query parameter for simplicity.
    """
    existing = get_user(user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_pw = get_password_hash(password)
    created_user = create_user(user, hashed_pw)

    # we only return the public part (no hashed password)
    return User(
        username=created_user.username,
        full_name=created_user.full_name,
        email=created_user.email,
        bio=created_user.bio,
        dob=created_user.dob,
    )


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

    return User(
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        bio=user.bio,
        dob=user.dob,
    )


@app.get("/me", response_model=User)
async def read_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently logged-in user.
    Requires the Authorization: Bearer <token> header.
    """
    return current_user