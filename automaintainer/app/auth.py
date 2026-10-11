import time
from typing import Optional, List
from enum import Enum
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel

class UserRole(str, Enum):
    VIEWER = "viewer"
    MAINTAINER = "maintainer"
    OPERATOR = "operator"
    SECURITY_ADMIN = "security-admin"
    PLATFORM_OPERATOR = "platform-operator"

class AuthUser(BaseModel):
    user_id: str
    username: str
    roles: List[UserRole]
    account_id: int

def is_platform_admin(user: AuthUser) -> bool:
    """
    Platform-level administrative authorization requires an explicit platform role
    (UserRole.SECURITY_ADMIN or UserRole.PLATFORM_OPERATOR).
    Does NOT use account_id == 0 numeric magic values for bypass.
    Tenant operators, maintainers, and viewers never bypass tenant boundaries.
    """
    return any(r in (UserRole.SECURITY_ADMIN, UserRole.PLATFORM_OPERATOR) for r in user.roles)

def get_jwt_secret() -> str:
    from automaintainer.config import get_settings
    try:
        settings = get_settings()
        secret = getattr(settings, "JWT_SECRET", None)
        if not secret or len(secret.strip()) < 32:
            raise RuntimeError("Fatal: JWT_SECRET is unconfigured or insecure.")
        return secret
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise e
        raise RuntimeError(f"Fatal: Failed to resolve JWT_SECRET: {e}") from e

JWT_ALGORITHM = "HS256"

security = HTTPBearer(auto_error=False)

def create_access_token(user: AuthUser, expires_in_seconds: int = 3600) -> str:
    payload = {
        "sub": user.user_id,
        "username": user.username,
        "roles": [r.value for r in user.roles],
        "account_id": user.account_id,
        "exp": int(time.time()) + expires_in_seconds,
        "iat": int(time.time())
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_test_token(username: str = "admin", roles: Optional[List[UserRole]] = None, account_id: int = 0) -> str:
    from automaintainer.config import get_settings
    try:
        settings = get_settings()
        if getattr(settings, "ENVIRONMENT", "production").lower().strip() in ("production", "staging"):
            raise RuntimeError("create_test_token() is strictly forbidden in production and staging environments.")
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise e
    user = AuthUser(
        user_id="test_operator",
        username=username,
        roles=roles or [UserRole.OPERATOR, UserRole.SECURITY_ADMIN],
        account_id=account_id
    )
    return create_access_token(user)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)) -> AuthUser:
    """
    Validates JWT token and extracts AuthUser.
    Strict authentication on all endpoints; no bypass.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required: missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return AuthUser(
            user_id=payload["sub"],
            username=payload["username"],
            roles=[UserRole(r) for r in payload.get("roles", ["viewer"])],
            account_id=payload.get("account_id", 0)
        )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )

def require_role(allowed_roles: List[UserRole]):
    def _role_checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        effective_roles = set(user.roles)
        if UserRole.PLATFORM_OPERATOR in effective_roles:
            effective_roles.add(UserRole.OPERATOR)
        for r in effective_roles:
            if r in allowed_roles:
                return user
        raise HTTPException(status_code=403, detail=f"Permission denied: required role in {[r.value for r in allowed_roles]}")
    return _role_checker
