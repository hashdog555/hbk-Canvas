import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from threading import Lock
from typing import Any, Dict, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field


COOKIE_NAME = "hbk_account_session"
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-.]{3,32}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_STORE = None


class AccountPayload(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=6, max_length=128)


class PasswordPayload(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)


def _now() -> int:
    return int(time.time())


def _public_user(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": record.get("id", ""),
        "username": record.get("username", ""),
        "created_at": record.get("created_at", 0),
        "last_login_at": record.get("last_login_at", 0),
    }


def _safe_username(username: str) -> str:
    value = (username or "").strip()
    if not USERNAME_RE.match(value) and not EMAIL_RE.match(value):
        raise HTTPException(status_code=400, detail="账号需为 3-32 位字母、数字、下划线、短横线、点，或邮箱")
    return value.lower()


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    raw_salt = base64.urlsafe_b64decode(salt.encode("ascii")) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, 260000)
    return (
        base64.urlsafe_b64encode(raw_salt).decode("ascii")
        + "$"
        + base64.urlsafe_b64encode(digest).decode("ascii")
    )


def _verify_password(password: str, encoded: str) -> bool:
    try:
        salt, expected = encoded.split("$", 1)
    except ValueError:
        return False
    actual = _hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(actual, expected)


class AccountStore:
    def __init__(self, data_dir: str):
        self.root = os.path.join(data_dir, "local_account")
        self.accounts_path = os.path.join(self.root, "accounts.json")
        self.secret_path = os.path.join(self.root, "session_secret")
        self.lock = Lock()
        os.makedirs(self.root, exist_ok=True)

    def _secret(self) -> bytes:
        if not os.path.exists(self.secret_path):
            with open(self.secret_path, "w", encoding="utf-8") as f:
                f.write(secrets.token_urlsafe(48))
        with open(self.secret_path, "r", encoding="utf-8") as f:
            return f.read().strip().encode("utf-8")

    def _read(self) -> Dict[str, Any]:
        if not os.path.exists(self.accounts_path):
            return {"users": []}
        with open(self.accounts_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("users"), list):
            return {"users": []}
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        tmp_path = self.accounts_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.accounts_path)

    def find_user(self, username: str) -> Optional[Dict[str, Any]]:
        clean = _safe_username(username)
        with self.lock:
            for user in self._read().get("users", []):
                if str(user.get("username", "")).lower() == clean:
                    return user
        return None

    def find_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for user in self._read().get("users", []):
                if user.get("id") == user_id:
                    return user
        return None

    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        clean = _safe_username(username)
        with self.lock:
            data = self._read()
            if any(str(u.get("username", "")).lower() == clean for u in data["users"]):
                raise HTTPException(status_code=409, detail="账号已存在")
            user = {
                "id": "acct_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16],
                "username": clean,
                "password_hash": _hash_password(password),
                "created_at": _now(),
                "last_login_at": _now(),
            }
            data["users"].append(user)
            self._write(data)
            return user

    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        clean = _safe_username(username)
        with self.lock:
            data = self._read()
            for user in data["users"]:
                if str(user.get("username", "")).lower() == clean and _verify_password(password, user.get("password_hash", "")):
                    user["last_login_at"] = _now()
                    self._write(data)
                    return user
        raise HTTPException(status_code=401, detail="账号或密码不正确")

    def update_password(self, user_id: str, old_password: str, new_password: str) -> Dict[str, Any]:
        with self.lock:
            data = self._read()
            for user in data["users"]:
                if user.get("id") == user_id:
                    if not _verify_password(old_password, user.get("password_hash", "")):
                        raise HTTPException(status_code=401, detail="旧密码不正确")
                    user["password_hash"] = _hash_password(new_password)
                    self._write(data)
                    return user
        raise HTTPException(status_code=401, detail="登录已失效")

    def sign_session(self, user_id: str) -> str:
        payload = json.dumps({"uid": user_id, "exp": _now() + SESSION_TTL_SECONDS}, separators=(",", ":")).encode("utf-8")
        body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        sig = hmac.new(self._secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def verify_session(self, token: str) -> Optional[Dict[str, Any]]:
        if not token or "." not in token:
            return None
        body, sig = token.rsplit(".", 1)
        expected = hmac.new(self._secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            padded = body + "=" * (-len(body) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except Exception:
            return None
        if int(payload.get("exp") or 0) < _now():
            return None
        return self.find_user_by_id(str(payload.get("uid") or ""))


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def _store() -> AccountStore:
    if _STORE is None:
        raise RuntimeError("Local account routes are not registered")
    return _STORE


def account_user_id(request: Request) -> str:
    try:
        user = _store().verify_session(request.cookies.get(COOKIE_NAME, ""))
    except Exception:
        return ""
    return user.get("id", "") if user else ""


def register_account_routes(app: FastAPI, data_dir: str) -> None:
    global _STORE
    _STORE = AccountStore(data_dir)
    router = APIRouter(prefix="/api/local-account", tags=["local-account"])

    @router.get("/me")
    async def me(request: Request):
        user = _STORE.verify_session(request.cookies.get(COOKIE_NAME, ""))
        return {"authenticated": bool(user), "user": _public_user(user) if user else None}

    @router.post("/register")
    async def register(payload: AccountPayload, response: Response):
        user = _STORE.create_user(payload.username, payload.password)
        _set_cookie(response, _STORE.sign_session(user["id"]))
        return {"ok": True, "user": _public_user(user)}

    @router.post("/login")
    async def login(payload: AccountPayload, response: Response):
        user = _STORE.authenticate(payload.username, payload.password)
        _set_cookie(response, _STORE.sign_session(user["id"]))
        return {"ok": True, "user": _public_user(user)}

    @router.post("/logout")
    async def logout(response: Response):
        _clear_cookie(response)
        return {"ok": True}

    @router.post("/password")
    async def password(payload: PasswordPayload, request: Request):
        user_id = account_user_id(request)
        if not user_id:
            raise HTTPException(status_code=401, detail="请先登录")
        user = _STORE.update_password(user_id, payload.old_password, payload.new_password)
        return {"ok": True, "user": _public_user(user)}

    app.include_router(router)
