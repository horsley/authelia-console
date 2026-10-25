import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from .oidc import OIDCLogin
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from typing import Literal

from .store import Problem, Store, atomic_write


class Version(BaseModel):
    version: int = Field(ge=0)


class Login(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=1000)


class UserBody(Version):
    username: str = Field(min_length=1, max_length=80)
    displayname: str = Field(min_length=1, max_length=100)
    email: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=1000)
    disabled: bool = False
    groups: list[str] = Field(default_factory=list, max_length=100)
    creating: bool = False


class GroupBody(Version):
    name: str = Field(min_length=1, max_length=80)
    members: list[str] = Field(default_factory=list, max_length=500)


class AppBody(Version):
    id: str = Field(default="", max_length=220)
    kind: Literal["oidc", "proxy"]
    creating: bool = False
    name: str = Field(min_length=1, max_length=100)
    client_id: str = Field(default="", max_length=200)
    public: bool = False
    client_secret: str = Field(default="", max_length=1000)
    redirect_uris: list[str] = Field(default_factory=list, max_length=50)
    scopes: list[str] = Field(
        default_factory=lambda: ["openid", "profile", "email", "groups"], max_length=20
    )
    domains: list[str] = Field(default_factory=list, max_length=20)
    access: Literal["all", "restricted", "deny"] = "restricted"
    subjects: list[str] = Field(default_factory=list, max_length=500)
    mfa: bool = True
    require_pkce: bool = True
    id_token_profile: bool | None = None
    bypass_resources: list[str] = Field(default_factory=list, max_length=50)
    bypass_methods: list[str] = Field(default_factory=list, max_length=30)


class ProxyRuleBody(Version):
    index: int | None = Field(default=None, ge=0)
    insert_before: int = Field(default=0, ge=0)
    policy: Literal["bypass", "deny", "one_factor", "two_factor"]
    domain: list[str] = Field(default_factory=list, max_length=50)
    domain_regex: list[str] = Field(default_factory=list, max_length=50)
    resources: list[str] = Field(default_factory=list, max_length=50)
    methods: list[str] = Field(default_factory=list, max_length=30)
    networks: list[str] = Field(default_factory=list, max_length=50)
    subject: list[list[str]] = Field(default_factory=list, max_length=100)


class RuleMove(Version):
    index: int = Field(ge=0)
    direction: Literal[-1, 1]


class DefaultPolicy(Version):
    policy: Literal["bypass", "deny", "one_factor", "two_factor"]


class PolicyCheck(Version):
    url: str = Field(min_length=1, max_length=2048)
    username: str = Field(default="", max_length=80)
    method: str = Field(default="GET", min_length=1, max_length=32)
    ip: str = Field(default="", max_length=60)


def create_app(store=None, password_hash=None, origin=None, oidc_client=None):
    store = store or Store(
        os.environ.get("CONFIG_DIR", "/config"),
        os.environ.get("STATE_DIR", "/data"),
        os.environ.get("HOOKS_SOCKET"),
        os.environ.get("AUTHELIA_ISSUER", ""),
        os.environ.get("USERS_FILE", "users_database.yml"),
    )
    password_hash = password_hash or os.environ.get("ADMIN_PASSWORD_HASH")
    auth_mode = os.environ.get("AUTH_MODE", "password")
    if auth_mode not in ("password", "oidc"):
        raise RuntimeError("Invalid AUTH_MODE")
    if auth_mode == "password" and not password_hash:
        raise RuntimeError(
            "Set ADMIN_PASSWORD_HASH using python -m app.password; no default password is provided"
        )
    origin = (
        origin or os.environ.get("PUBLIC_ORIGIN", "http://127.0.0.1:8096")
    ).rstrip("/")
    public = urlsplit(origin)
    if public.scheme not in ("http", "https") or not public.netloc or public.path:
        raise RuntimeError("PUBLIC_ORIGIN must be an HTTP(S) origin without a path")
    base_path = os.environ.get("BASE_PATH", "").rstrip("/")
    if base_path and (not base_path.startswith("/") or ".." in base_path):
        raise RuntimeError("Invalid BASE_PATH")
    secure = public.scheme == "https"
    key_path = store.state / "session-key"
    if not key_path.exists():
        atomic_write(key_path, secrets.token_hex(32))
    signing_key = key_path.read_text().encode()
    app = FastAPI(
        title="Authelia Console", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.store = store
    oidc = None
    if auth_mode == "oidc":
        if not secure:
            raise RuntimeError("OIDC requires an HTTPS PUBLIC_ORIGIN")
        oidc = OIDCLogin(store.state, os.environ.get("OIDC_ISSUER", ""),
                         os.environ.get("OIDC_CLIENT_ID", ""),
                         os.environ.get("OIDC_CLIENT_SECRET", ""),
                         [u.strip() for u in os.environ.get("OIDC_ADMIN_USERS", "").split(",") if u.strip()],
                         client=oidc_client)
        app.add_middleware(SessionMiddleware, secret_key=hmac.new(signing_key, b"oidc-state", hashlib.sha256).hexdigest(),
                           session_cookie="authelia_console_oidc", path=base_path+"/",
                           max_age=600, same_site="lax", https_only=True)
    failures = defaultdict(list)
    revoked = {}
    cookie_name = "authelia_console_session"
    cookie_path = base_path + "/"

    def sign(payload):
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        return (
            body
            + "."
            + hmac.new(signing_key, body.encode(), hashlib.sha256).hexdigest()
        )

    def session(request):
        raw = request.cookies.get(cookie_name, "")
        try:
            body, signature = raw.rsplit(".", 1)
            if not hmac.compare_digest(
                signature,
                hmac.new(signing_key, body.encode(), hashlib.sha256).hexdigest(),
            ):
                return None
            data = json.loads(base64.urlsafe_b64decode(body))
            if data.get("auth", "password") != auth_mode:
                return None
            if auth_mode == "oidc" and data.get("username") not in oidc.users:
                return None
            if data["exp"] < time.time() or data["id"] in revoked:
                return None
            return data
        except (ValueError, KeyError, TypeError):
            return None

    @app.exception_handler(Problem)
    async def problem_handler(request, error):
        return JSONResponse({"error": error.message}, status_code=error.status)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # FastAPI's default details can echo password/secret values from input.
        return JSONResponse(
            {"error": "输入内容不符合要求，请检查字段格式和长度。"}, status_code=422
        )

    @app.middleware("http")
    async def guard(request, call_next):
        host = request.headers.get("host", "")
        if host != public.netloc:
            return JSONResponse(
                {"error": "请求 Host 与 PUBLIC_ORIGIN 不匹配"}, status_code=400
            )
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("origin") != origin:
                return JSONResponse({"error": "请求来源校验失败"}, status_code=403)
            try:
                size = int(request.headers.get("content-length", "0"))
            except ValueError:
                size = 1000001
            if size > 1000000:
                return JSONResponse({"error": "请求过大"}, status_code=413)
        if request.url.path.startswith("/api/") and request.url.path not in ("/api/login", "/api/auth-config"):
            s = session(request)
            if not s:
                return JSONResponse({"error": "请先登录"}, status_code=401)
            if request.method not in ("GET", "HEAD") and not hmac.compare_digest(
                request.headers.get("x-csrf-token", ""), s["csrf"]
            ):
                return JSONResponse(
                    {"error": "CSRF 校验失败，请刷新页面"}, status_code=403
                )
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
            }
        )
        return response

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/api/auth-config")
    def auth_config():
        return {"mode": auth_mode, "login_url": base_path+"/auth/login"}

    @app.get("/auth/login")
    async def oidc_login(request: Request):
        if oidc is None:
            raise Problem("未启用 OIDC", 404)
        try:
            return await oidc.begin(request, origin+base_path+"/auth/callback")
        except Problem:
            raise
        except Exception:
            raise Problem("身份提供方暂时不可用，请稍后重试", 502)

    @app.get("/auth/callback")
    async def oidc_callback(request: Request):
        if oidc is None:
            raise Problem("未启用 OIDC", 404)
        try:
            identity = await oidc.finish(request)
        except Problem:
            request.session.clear()
            raise
        except Exception:
            request.session.clear()
            raise Problem("SSO 登录校验失败，请重新从工作台开始登录", 400)
        request.session.clear()
        s = {"id":secrets.token_hex(24), "exp":time.time()+28800,
             "csrf":secrets.token_hex(24), **identity}
        response = RedirectResponse(base_path+"/", status_code=303)
        response.set_cookie(cookie_name, sign(s), httponly=True, secure=True,
                            samesite="strict", path=cookie_path, max_age=28800)
        return response

    @app.post("/api/login")
    def login(body: Login, request: Request):
        if auth_mode != "password":
            raise Problem("工作台已改用 Authelia 登录", 404)
        now = time.time()
        ip = request.client.host if request.client else "local"
        failures[ip] = [t for t in failures[ip] if now - t < 600]
        if len(failures[ip]) >= 8:
            raise Problem("登录失败次数过多，请 10 分钟后再试", 429)
        try:
            valid = PasswordHasher().verify(password_hash, body.password)
        except (VerificationError, InvalidHashError):
            valid = False
        if not valid or not hmac.compare_digest(
            body.username, os.environ.get("ADMIN_USERNAME", "admin")
        ):
            failures[ip].append(now)
            raise Problem("用户名或密码不正确", 401)
        failures.pop(ip, None)
        for sid in list(revoked):
            if revoked[sid] < now:
                revoked.pop(sid)
        s = {
            "id": secrets.token_hex(24),
            "exp": now + 28800,
            "csrf": secrets.token_hex(24),
        }
        response = JSONResponse(
            {"csrf": s["csrf"], "username": os.environ.get("ADMIN_USERNAME", "admin")}
        )
        response.set_cookie(
            cookie_name,
            sign(s),
            httponly=True,
            secure=secure,
            samesite="strict",
            path=cookie_path,
            max_age=28800,
        )
        return response

    @app.get("/api/session")
    def current_session(request: Request):
        return {
            "csrf": session(request)["csrf"],
            "username": session(request).get("username", os.environ.get("ADMIN_USERNAME", "admin")),
            "auth_mode": auth_mode,
        }

    @app.post("/api/logout")
    def logout(request: Request):
        s = session(request)
        revoked[s["id"]] = s["exp"]
        response = JSONResponse({"ok": True})
        response.delete_cookie(cookie_name, path=cookie_path)
        return response

    @app.get("/api/state")
    def state():
        return store.view()

    @app.post("/api/users")
    def users(body: UserBody):
        store.upsert_user(body)
        return {"ok": True}

    @app.delete("/api/users/{username}")
    def delete_user(username: str, body: Version):
        store.delete_user(username, body.version)
        return {"ok": True}

    @app.post("/api/groups")
    def groups(body: GroupBody):
        store.group(body.name, body.members, body.version)
        return {"ok": True}

    @app.delete("/api/groups/{name}")
    def delete_group(name: str, body: Version):
        store.group(name, [], body.version, delete=True)
        return {"ok": True}

    @app.post("/api/applications")
    def applications(body: AppBody):
        store.upsert_app(body)
        return {"ok": True}

    @app.delete("/api/applications/{app_id:path}")
    def delete_app(app_id: str, body: Version):
        store.delete_app(app_id, body.version)
        return {"ok": True}

    @app.post("/api/secret")
    def secret():
        return {"secret": secrets.token_urlsafe(48)}

    @app.post("/api/proxy-rules")
    def proxy_rule(body: ProxyRuleBody):
        store.upsert_proxy_rule(body)
        return {"ok": True}

    @app.delete("/api/proxy-rules/{index}")
    def delete_proxy_rule(index: int, body: Version):
        store.delete_proxy_rule(index, body.version)
        return {"ok": True}

    @app.post("/api/proxy-rules/move")
    def move_proxy_rule(body: RuleMove):
        store.move_proxy_rule(body.index, body.direction, body.version)
        return {"ok": True}

    @app.post("/api/proxy-default")
    def proxy_default(body: DefaultPolicy):
        store.set_proxy_default(body.policy, body.version)
        return {"ok": True}

    @app.post("/api/check-policy")
    def check_policy(body: PolicyCheck):
        return store.check_policy(body)

    @app.get("/api/preview")
    def preview():
        return store.preview()

    @app.post("/api/validate")
    def validate(body: Version):
        return store.publish(body.version, check_only=True)

    @app.post("/api/publish")
    def publish(body: Version):
        return store.publish(body.version)

    @app.post("/api/discard")
    def discard(body: Version):
        store.discard(body.version)
        return {"ok": True}

    @app.post("/api/rollback/{snapshot_id}")
    def rollback(snapshot_id: str, body: Version):
        return store.rollback(snapshot_id, body.version)

    static = Path(__file__).parent / "static"
    app.mount("/assets", StaticFiles(directory=static), name="assets")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
