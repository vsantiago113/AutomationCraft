from datetime import datetime, timedelta, timezone
from typing import Annotated, Union

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
import logging

# Constants
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = True

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fake users database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secret"),  # hashed password
        "disabled": False,
    },
}


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str  # Added refresh token
    scope: str  # Added scope
    expires_in: int  # Added expires_in


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"cmdb": "Access CMDB information."},
)

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        logger.debug(f"User {username} not found.")
        return False
    if not verify_password(password, user.hashed_password):
        logger.debug(f"Password for user {username} is incorrect.")
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.debug("Token payload does not contain 'sub'.")
            raise credentials_exception
        token_data = TokenData(username=username)
    except (InvalidTokenError, ValidationError) as e:
        logger.debug(f"Token validation error: {str(e)}")
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        logger.debug(f"User {token_data.username} not found.")
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        logger.debug(f"User {current_user.username} is disabled.")
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
@app.post("/oauth_token_do")  # Added this line to support /oauth_token_do
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        logger.debug(f"Authentication failed for user {form_data.username}.")
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    refresh_token = create_refresh_token(
        data={"sub": user.username},
        expires_delta=refresh_token_expires,
    )
    scope = " ".join(form_data.scopes) if form_data.scopes else "all"  # Assign all access if scope is empty
    logger.debug(f"Access token and refresh token created for user {user.username}.")
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token,
        scope=scope,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Adding expires_in
    )


@app.post("/refresh_token")
async def refresh_access_token(refresh_token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except (InvalidTokenError, ValidationError) as e:
        logger.debug(f"Refresh token validation error: {str(e)}")
        raise credentials_exception

    user = get_user(fake_users_db, username=username)
    if user is None:
        logger.debug(f"User {username} not found.")
        raise credentials_exception

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    logger.debug(f"New access token created for user {user.username}.")
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60  # Adding expires_in
    }


@app.get("/api/now/table/cmdb_ci_server")
async def get_cmdb_data(request: Request, current_user: User = Depends(get_current_active_user)):
    logger.debug(f"Current user accessing CMDB data: {current_user.username}")
    query_params = request.query_params.get('sysparm_query')
    fields = request.query_params.get('sysparm_fields')
    limit = int(request.query_params.get('sysparm_limit', 100))

    logger.info(f"Query params: {query_params}, fields: {fields}, limit: {limit}")

    mock_data = [
        {
            'sys_id': '1',
            'name': 'Host1',
            'host_name': 'host1.example.com',
            'u_cpu_architecture': 'x86_64',
            'u_patch_slot': 'slot1',
            'u_patching_group': 'group1',
            'os': {
                'os_version': 'Red Hat Enterprise Linux 7'
            }
        },
        {
            'sys_id': '2',
            'name': 'Host2',
            'host_name': 'host2.example.com',
            'u_cpu_architecture': 'x86_64',
            'u_patch_slot': 'slot2',
            'u_patching_group': 'group2',
            'os': {
                'os_version': 'CentOS 7'
            }
        }
    ][:limit]

    logger.debug("Returning mock CMDB data")
    return {'result': mock_data}


if __name__ == "__main__":
    import uvicorn
    logger.debug("Starting application with Uvicorn")
    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="selfsigned.key", ssl_certfile="selfsigned.crt", log_level="debug")
