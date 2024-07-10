from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
import logging

# Constants
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

basic_auth = HTTPBasic()

app = FastAPI()

def verify_password(plain_password, hashed_password):
    logger.debug("Verifying password")
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    logger.debug(f"Retrieving user: {username}")
    if username in db:
        user_dict = db[username]
        logger.debug(f"User found: {username}")
        return UserInDB(**user_dict)
    logger.debug(f"User not found: {username}")
    return None

def authenticate_user(fake_db, username: str, password: str):
    logger.debug(f"Authenticating user: {username}")
    user = get_user(fake_db, username)
    if not user:
        logger.info(f"User not found: {username}")
        return False
    if not verify_password(password, user.hashed_password):
        logger.info(f"Password verification failed for user: {username}")
        return False
    logger.info(f"Password verified for user: {username}")
    return user

def get_current_basic_user(credentials: HTTPBasicCredentials = Depends(basic_auth)):
    logger.info(f"Received basic auth credentials: {credentials.username}")
    user = authenticate_user(fake_users_db, credentials.username, credentials.password)
    if not user:
        logger.info(f"Authentication failed for user: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    logger.info(f"Authenticated user: {user.username}")
    return user

async def get_current_active_user(
    basic_user: Annotated[User, Depends(get_current_basic_user)] = None,
):
    logger.debug("Getting current active user")
    user = basic_user
    if user is None:
        logger.error("No user authenticated")
        raise HTTPException(status_code=400, detail="No user authenticated")
    if user.disabled:
        logger.error(f"User is disabled: {user.username}")
        raise HTTPException(status_code=400, detail="Inactive user")
    logger.debug(f"Current active user: {user.username}")
    return user

@app.get("/api/now/table/cmdb_ci_server")
async def get_cmdb_data(request: Request, current_user: User = Depends(get_current_active_user)):
    logger.debug(f"Current user accessing cmdb data: {current_user.username}")
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
