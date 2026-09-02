from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from .config import settings


SECRET_KEY = settings.jwt_secret
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.jwt_expire_minutes


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    auto_error=False,
)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


async def get_token_from_request(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
) -> Optional[str]:

    # Authorization header takes priority.
    if token:
        return token

    query_token = request.query_params.get("token")
    if query_token:
        return query_token

    # Fall back to the HTTP-only authentication cookie.
    cookie_token = request.cookies.get(
        settings.auth_cookie_name
    )

    if cookie_token:
        if cookie_token.startswith("Bearer "):
            return cookie_token[7:]

        return cookie_token

    return None


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(get_token_from_request),
):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )

    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    from .main import db

    placeholder = "%s" if db.is_postgres else "?"

    user = db.query_one(
        f"""
        SELECT id, username, role
        FROM users
        WHERE id = {placeholder}
        """,
        (user_id,),
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


async def require_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    return current_user


async def require_admin(
    current_user: dict = Depends(get_current_user),
) -> dict:

    if current_user["role"] != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized",
        )

    return current_user


auth_router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


@auth_router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: RegisterRequest,
):
    from .main import db

    username = data.username.strip()

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters",
        )

    if len(username) > 100:
        raise HTTPException(
            status_code=400,
            detail="Username is too long",
        )

    if len(data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters",
        )

    placeholder = "%s" if db.is_postgres else "?"

    existing = db.query_one(
        f"""
        SELECT id
        FROM users
        WHERE username = {placeholder}
        """,
        (username,),
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    import uuid

    user_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    password_hash = get_password_hash(data.password)

    db.execute(
        f"""
        INSERT INTO users(
            id,
            username,
            password_hash,
            role,
            created_at
        )
        VALUES(
            {placeholder},
            {placeholder},
            {placeholder},
            {placeholder},
            {placeholder}
        )
        """,
        (
            user_id,
            username,
            password_hash,
            "USER",
            created_at,
        ),
    )

    return {
        "id": user_id,
        "username": username,
        "role": "USER",
    }


@auth_router.post("/login")
async def login(
    response: Response,
    data: LoginRequest,
):
    from .main import db

    placeholder = "%s" if db.is_postgres else "?"

    user = db.query_one(
        f"""
        SELECT
            id,
            username,
            password_hash,
            role
        FROM users
        WHERE username = {placeholder}
        """,
        (data.username.strip(),),
    )

    if not user or not verify_password(
        data.password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token(
        data={
            "sub": user["id"],
        }
    )

    response.set_cookie(
        key=settings.auth_cookie_name,
        value=f"Bearer {access_token}",
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        },
    }


@auth_router.post("/logout")
async def logout(
    response: Response,
):
    response.delete_cookie(
        key=settings.auth_cookie_name,
        path="/",
    )

    return {
        "status": "ok",
    }


@auth_router.get("/me")
async def get_me(
    current_user: dict = Depends(require_user),
):
    return current_user


@auth_router.get("/users")
async def list_users(
    current_user: dict = Depends(require_admin),
):
    from .main import db

    users = db.query_all(
        """
        SELECT
            id,
            username,
            role,
            created_at
        FROM users
        ORDER BY created_at DESC
        """
    )

    return users


class UpdateRoleRequest(BaseModel):
    role: str


@auth_router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    data: UpdateRoleRequest,
    current_user: dict = Depends(require_admin),
):
    if data.role not in {"ADMIN", "USER"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid role",
        )

    from .main import db

    placeholder = "%s" if db.is_postgres else "?"

    db.execute(
        f"""
        UPDATE users
        SET role = {placeholder}
        WHERE id = {placeholder}
        """,
        (
            data.role,
            user_id,
        ),
    )

    return {
        "status": "ok",
    }


@auth_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_admin),
):
    if user_id == current_user["id"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete yourself",
        )

    from .main import db

    placeholder = "%s" if db.is_postgres else "?"

    db.execute(
        f"""
        DELETE FROM users
        WHERE id = {placeholder}
        """,
        (user_id,),
    )

    return {
        "status": "ok",
    }