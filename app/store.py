"""Round-trip configuration editing and optimistic, recoverable publication."""

import copy
import difflib
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from argon2 import PasswordHasher
from ruamel.yaml import YAML
from .proxy_rules import edit_rule, generated_rules

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,79}$")
POLICY_PREFIX = "console_"


class Problem(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def load_yaml(text):
    # Authelia evaluates Go templates BEFORE YAML. Plain YAML parsers otherwise
    # reinterpret an unquoted {{ secret ... }} as a nested mapping and corrupt it.
    templates = {}

    def protect(match):
        expression = match.group(0)
        marker = (
            "AUTHELIA_CONSOLE_TEMPLATE_"
            + hashlib.sha256(expression.encode()).hexdigest()
        )
        templates[marker] = expression
        return marker

    text = re.sub(r"{{.*?}}", protect, text, flags=re.S)
    y = YAML()
    y.preserve_quotes = True
    y.allow_duplicate_keys = False
    doc = y.load(text)
    if not isinstance(doc, dict):
        raise Problem("配置文件必须是 YAML 对象")
    doc._console_templates = templates
    return doc


def dump_yaml(doc):
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    out = io.StringIO()
    y.dump(doc, out)
    text = out.getvalue()
    for marker, expression in getattr(doc, "_console_templates", {}).items():
        text = text.replace(marker, expression)
    return text


def atomic_write(path, content, mode=0o600):
    """Replace in the same directory, fsync, and preserve existing permissions."""
    path = Path(path)
    old = path.stat() if path.exists() else None
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fchmod(f.fileno(), stat.S_IMODE(old.st_mode) if old else mode)
            if old and hasattr(os, "fchown"):
                os.fchown(f.fileno(), old.st_uid, old.st_gid)
            os.fsync(f.fileno())
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temp.unlink(missing_ok=True)


def fingerprint(config, users):
    return hashlib.sha256((config + "\0" + users).encode()).hexdigest()


def redact(doc):
    """Preview never contains passwords, signing keys, client secrets or tokens."""
    if isinstance(doc, dict):
        return {
            str(k): "••••••"
            if re.search(r"secret|password|(^|_)key$|token$", str(k), re.I)
            else redact(v)
            for k, v in doc.items()
        }
    if isinstance(doc, list):
        return [redact(v) for v in doc]
    return str(doc) if not isinstance(doc, (str, int, float, bool, type(None))) else doc


class Store:
    def __init__(
        self,
        config_dir,
        state_dir,
        hooks_socket=None,
        issuer="",
        users_name="users_database.yml",
    ):
        self.root, self.state = Path(config_dir), Path(state_dir)
        self.config_path, self.users_path = (
            self.root / "configuration.yml",
            self.root / users_name,
        )
        if Path(users_name).name != users_name:
            raise RuntimeError("USERS_FILE must be a file name within CONFIG_DIR")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.hooks_socket, self.issuer = hooks_socket, issuer.rstrip("/")
        self.mutex = threading.RLock()
        self.lock_depth = threading.local()
        self.recover()

    @contextmanager
    def locked(self):
        with self.mutex:
            if getattr(self.lock_depth, "active", False):
                yield
                return
            with open(self.state / ".lock", "a+") as lock:
                os.chmod(self.state / ".lock", 0o600)
                fcntl.flock(lock, fcntl.LOCK_EX)
                self.lock_depth.active = True
                try:
                    yield
                finally:
                    self.lock_depth.active = False
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def read_live(self):
        return self.config_path.read_text(), self.users_path.read_text()

    def read_json(self, name, default=None):
        p = self.state / name
        return json.loads(p.read_text()) if p.exists() else copy.deepcopy(default)

    def write_json(self, name, data):
        atomic_write(self.state / name, json.dumps(data, ensure_ascii=False, indent=2))

    def hook(self, action, payload=None):
        if not self.hooks_socket:
            raise Problem(
                "当前未连接发布代理，草稿可编辑；连接代理后才能校验、应用或回滚。", 503
            )
        try:
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=self.hooks_socket), timeout=100
            ) as client:
                r = client.post("http://localhost/" + action, json=payload)
                result = r.json()
                if r.status_code != 200:
                    raise Problem(result.get("error", "发布代理执行失败"), 422)
                return result
        except (httpx.HTTPError, ValueError) as e:
            raise Problem("发布代理不可用，请检查代理服务。", 503) from e

    def recover(self):
        """A crash between the two renames must never silently leave mixed files."""
        journal = self.read_json("transaction.json")
        if journal:
            with self.locked():
                if self.hooks_socket:
                    self.hook("stop")
                    self.restore_files(journal)
                    self.hook("restart")
                else:
                    raise RuntimeError(
                        "Unfinished transaction requires publication agent for recovery"
                    )
                (self.state / "transaction.json").unlink()

    def restore_files(self, snapshot):
        atomic_write(self.config_path, snapshot["config"])
        atomic_write(self.users_path, snapshot["users"])
        self.write_json("metadata.json", snapshot.get("metadata", {}))

    def draft(self):
        d = self.read_json("draft.json")
        if d:
            return d
        config, users = self.read_live()
        backend = load_yaml(config).get("authentication_backend", {})
        if "file" not in backend:
            raise Problem(
                "第一版仅支持 Authelia 文件用户后端，当前实例使用 LDAP。", 422
            )
        expected = Path(str(backend["file"].get("path", ""))).name
        if expected != self.users_path.name:
            raise Problem(f"用户文件不匹配，需将 USERS_FILE 设置为 {expected}", 422)
        metadata = self.read_json("metadata.json", {})
        if (
            metadata.get("managed_rule_count")
            and metadata.get("config_digest")
            != hashlib.sha256(config.encode()).hexdigest()
        ):
            raise Problem(
                "线上配置曾被外部修改，代理应用元数据可能失配；请先由管理员同步元数据，避免误改规则顺序。",
                409,
            )
        return {
            "base": fingerprint(config, users),
            "base_config": config,
            "base_users": users,
            "config": config,
            "users": users,
            "metadata": metadata,
            "changes": [],
            "version": self.read_json("generation.json", 0),
        }

    def save(self, d, message):
        d["version"] = max(d["version"], self.read_json("generation.json", 0)) + 1
        d["changes"].append(message)
        self.write_json("generation.json", d["version"])
        self.write_json("draft.json", d)

    def assert_version(self, d, version):
        if version != d["version"]:
            raise Problem("草稿已被其他页面修改，请刷新后再操作。", 409)

    def policy_view(self, config, client):
        name = str(client.get("authorization_policy", "two_factor"))
        if name in ("one_factor", "two_factor"):
            return {
                "access": "all",
                "subjects": [],
                "mfa": name == "two_factor",
                "advanced": False,
            }
        p = (
            config.get("identity_providers", {})
            .get("oidc", {})
            .get("authorization_policies", {})
            .get(name, {})
        )
        rules = p.get("rules", [])
        if p.get("default_policy") == "deny" and len(rules) == 1:
            r = rules[0]
            subjects = r.get("subject", [])
            if isinstance(subjects, str):
                subjects = [subjects]
            if (
                set(r) <= {"policy", "subject"}
                and all(isinstance(s, str) for s in subjects)
                and r.get("policy") in ("one_factor", "two_factor")
            ):
                return {
                    "access": "restricted",
                    "subjects": list(subjects),
                    "mfa": r["policy"] == "two_factor",
                    "advanced": False,
                }
        if (
            name.startswith(POLICY_PREFIX)
            and p.get("default_policy") == "deny"
            and rules
            and all(r.get("policy") == "deny" for r in rules)
        ):
            return {"access": "deny", "subjects": [], "mfa": True, "advanced": False}
        return {
            "access": "custom",
            "subjects": [],
            "mfa": True,
            "advanced": True,
            "policy": name,
        }

    def profile_claims_view(self, config, client):
        policy = client.get("claims_policy")
        if not policy:
            return False
        name = POLICY_PREFIX + "claims_" + hashlib.sha256(str(client["client_id"]).encode()).hexdigest()[:20]
        value = config.get("identity_providers", {}).get("oidc", {}).get("claims_policies", {}).get(policy)
        if policy == name and value == {"id_token": ["name", "email", "email_verified", "preferred_username"]}:
            return True
        return None  # Preserve custom policies instead of guessing their semantics.

    def view(self):
        with self.locked():
            d = self.draft()
            c, u = load_yaml(d["config"]), load_yaml(d["users"])
            users = [
                {
                    "username": name,
                    "displayname": str(v.get("displayname", name)),
                    "email": str(v.get("email", "")),
                    "disabled": bool(v.get("disabled", False)),
                    "groups": list(v.get("groups", [])),
                }
                for name, v in u.get("users", {}).items()
            ]
            groups = sorted(
                set(d["metadata"].get("groups", []))
                | {g for v in users for g in v["groups"]}
            )
            apps = []
            for client in (
                c.get("identity_providers", {}).get("oidc", {}).get("clients", [])
            ):
                apps.append(
                    {
                        "id": "oidc:" + str(client["client_id"]),
                        "kind": "oidc",
                        "client_id": str(client["client_id"]),
                        "name": str(client.get("client_name", client["client_id"])),
                        "public": bool(client.get("public", False)),
                        "redirect_uris": list(client.get("redirect_uris", [])),
                        "scopes": list(
                            client.get(
                                "scopes", ["openid", "profile", "email", "groups"]
                            )
                        ),
                        "has_secret": bool(client.get("client_secret")),
                        "id_token_profile": self.profile_claims_view(c, client),
                        "require_pkce": bool(client.get("require_pkce", False)),
                        **self.policy_view(c, client),
                    }
                )
            apps += list(d["metadata"].get("proxy_apps", {}).values())
            live_config, live_users = self.read_live()
            legacy_rules = c.get("access_control", {}).get("rules", [])
            managed_count = d["metadata"].get("managed_rule_count", 0)
            return {
                "users": users,
                "groups": groups,
                "applications": apps,
                "version": d["version"],
                "changes": d["changes"],
                "conflict": fingerprint(live_config, live_users) != d["base"],
                "issuer": self.issuer,
                "can_publish": bool(self.hooks_socket),
                "legacy_rules": redact(legacy_rules[managed_count:]),
                "proxy_rules": [
                    {
                        "position": i + 1,
                        "index": i - managed_count if i >= managed_count else None,
                        "managed": i < managed_count,
                        "rule": redact(rule),
                    }
                    for i, rule in enumerate(legacy_rules)
                ],
                "managed_rule_count": managed_count,
                "default_policy": c.get("access_control", {}).get(
                    "default_policy", "deny"
                ),
                "history": [
                    {
                        k: v
                        for k, v in s.items()
                        if k not in ("config", "users", "metadata")
                    }
                    for s in self.read_json("history.json", [])
                ],
                "watch_users": bool(
                    c.get("authentication_backend", {})
                    .get("file", {})
                    .get("watch", False)
                ),
            }

    def upsert_user(self, body):
        with self.locked():
            d = self.draft()
            self.assert_version(d, body.version)
            if not ID.fullmatch(body.username):
                raise Problem(
                    "用户名仅支持字母、数字、点、横线、下划线和 @，最长 80 位"
                )
            u = load_yaml(d["users"])
            users = u.setdefault("users", {})
            old = users.get(body.username)
            if body.creating and old:
                raise Problem("该用户名已存在", 409)
            if not body.creating and not old:
                raise Problem("用户不存在", 404)
            if not old and not body.password:
                raise Problem("新用户必须设置密码")
            if body.password and len(body.password) < 12:
                raise Problem("密码至少需要 12 个字符")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", body.email):
                raise Problem(
                    "请填写有效邮箱，Authelia 的二次验证注册和密码恢复需要使用它"
                )
            existing_groups = set(d["metadata"].get("groups", [])) | {
                g for v in users.values() for g in v.get("groups", [])
            }
            if not set(body.groups) <= existing_groups:
                raise Problem("所选用户组不存在")
            v = copy.deepcopy(old) if old else {}
            v.update(
                displayname=body.displayname,
                email=body.email,
                disabled=body.disabled,
                groups=sorted(set(body.groups)),
            )
            if body.password:
                v["password"] = HASHER.hash(body.password)
            users[body.username] = v
            d["users"] = dump_yaml(u)
            self.save(d, f"{'创建' if not old else '更新'}用户 {body.username}")

    def delete_user(self, username, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            u = load_yaml(d["users"])
            if username not in u.get("users", {}):
                raise Problem("用户不存在", 404)
            # Avoid hidden policy rewrites when deleting a referenced principal.
            c = load_yaml(d["config"])
            if f"user:{username}" in json.dumps(c, ensure_ascii=False):
                raise Problem("该用户仍被访问策略引用，请先移除应用或高级规则中的授权")
            del u["users"][username]
            d["users"] = dump_yaml(u)
            self.save(d, f"删除用户 {username}")

    def group(self, name, members, version, delete=False):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            if not ID.fullmatch(name):
                raise Problem("用户组名称格式无效")
            u = load_yaml(d["users"])
            users = u.get("users", {})
            if not set(members) <= set(users):
                raise Problem("用户组包含不存在的用户")
            if delete and f"group:{name}" in json.dumps(
                load_yaml(d["config"]), ensure_ascii=False
            ):
                raise Problem("该组仍被访问策略引用，请先移除相关授权")
            names = set(d["metadata"].get("groups", [])) | {
                g for v in users.values() for g in v.get("groups", [])
            }
            if delete:
                names.discard(name)
            else:
                names.add(name)
            for username, v in users.items():
                groups = set(v.get("groups", []))
                groups.discard(name)
                if not delete and username in members:
                    groups.add(name)
                v["groups"] = sorted(groups)
            d["metadata"]["groups"] = sorted(names)
            d["users"] = dump_yaml(u)
            self.save(d, f"{'删除' if delete else '更新'}用户组 {name}")

    def upsert_app(self, body):
        with self.locked():
            d = self.draft()
            self.assert_version(d, body.version)
            c = load_yaml(d["config"])
            u = load_yaml(d["users"])
            users = set(u.get("users", {}))
            groups = set(d["metadata"].get("groups", [])) | {
                g for v in u.get("users", {}).values() for g in v.get("groups", [])
            }
            valid = {"user:" + n for n in users} | {"group:" + n for n in groups}
            if not set(body.subjects) <= valid:
                raise Problem("授权包含不存在的用户或组")
            if body.access == "restricted" and not body.subjects:
                raise Problem("指定用户模式至少选择一个用户或组")
            if body.kind == "oidc":
                oidc = c.setdefault("identity_providers", {}).setdefault("oidc", {})
                clients = oidc.setdefault("clients", [])
                client = next(
                    (x for x in clients if str(x["client_id"]) == body.client_id), None
                )
                if body.creating and client:
                    raise Problem("Client ID 已存在", 409)
                if not body.creating and (
                    not client or body.id != "oidc:" + body.client_id
                ):
                    raise Problem("应用不存在或 Client ID 已改变", 404)
                if client and self.policy_view(c, client)["advanced"]:
                    raise Problem(
                        "该应用使用高级策略，第一版保留其原始配置，暂不支持表单编辑",
                        422,
                    )
                if not body.client_id or len(body.client_id) > 200:
                    raise Problem("Client ID 长度应为 1–200 个字符")
                if not body.redirect_uris:
                    raise Problem("至少需要一个回调地址")
                for uri in body.redirect_uris:
                    p = urlsplit(uri)
                    if (
                        not p.scheme
                        or p.fragment
                        or p.username
                        or p.password
                        or "*" in uri
                        or (p.scheme in ("http", "https") and not p.hostname)
                    ):
                        raise Problem(
                            "回调地址必须是完整 URI，不能包含通配符、账号密码或片段"
                        )
                    if p.scheme == "http" and p.hostname not in (
                        "localhost",
                        "127.0.0.1",
                        "::1",
                    ):
                        raise Problem("HTTP 回调仅允许本机地址；其他地址请使用 HTTPS")
                new = client is None
                if new:
                    client = {
                        "client_id": body.client_id,
                        "response_types": ["code"],
                        "grant_types": ["authorization_code"],
                        "require_pkce": body.require_pkce,
                        "pkce_challenge_method": "S256",
                        "consent_mode": "auto",
                    }
                    if "offline_access" in body.scopes:
                        client["grant_types"].append("refresh_token")
                    clients.append(client)
                client["client_name"] = body.name
                if not new and bool(client.get("public", False)) != body.public:
                    raise Problem(
                        "现有应用的公开/机密类型不可直接切换，请新建 Client 迁移"
                    )
                client["public"] = body.public
                client["redirect_uris"] = list(dict.fromkeys(body.redirect_uris))
                if (
                    not set(body.scopes)
                    <= {"openid", "profile", "email", "groups", "offline_access"}
                    or "openid" not in body.scopes
                ):
                    raise Problem(
                        "Scope 必须包含 openid，且只能选择后台支持的标准 Scope"
                    )
                client["scopes"] = body.scopes
                if body.public:
                    client["token_endpoint_auth_method"] = "none"
                    client.pop("client_secret", None)
                elif new:
                    if not body.client_secret or len(body.client_secret) < 32:
                        raise Problem("新机密客户端需要至少 32 字符的 Secret")
                    client["client_secret"] = HASHER.hash(body.client_secret)
                elif body.client_secret:
                    raise Problem(
                        "第一版暂不支持轮换已有客户端 Secret，以避免现有应用中断"
                    )
                policy_name = (
                    POLICY_PREFIX
                    + hashlib.sha256(body.client_id.encode()).hexdigest()[:20]
                )
                policies = oidc.setdefault("authorization_policies", {})
                factor = "two_factor" if body.mfa else "one_factor"
                if body.access == "all":
                    client["authorization_policy"] = factor
                    policies.pop(policy_name, None)
                else:
                    rule = (
                        {"policy": factor, "subject": sorted(set(body.subjects))}
                        if body.access == "restricted"
                        else {"policy": "deny", "subject": ["group:__console_nobody__"]}
                    )
                    policies[policy_name] = {"default_policy": "deny", "rules": [rule]}
                    client["authorization_policy"] = policy_name
                if not policies:
                    oidc.pop("authorization_policies", None)
                if body.id_token_profile is not None:
                    if not {"profile", "email"} <= set(body.scopes) and body.id_token_profile:
                        raise Problem("ID Token 用户资料需要 profile 和 email Scope")
                    claims_name = POLICY_PREFIX + "claims_" + hashlib.sha256(body.client_id.encode()).hexdigest()[:20]
                    if client.get("claims_policy") not in (None, claims_name):
                        raise Problem("现有客户端使用自定义 Claims 策略，保持原有配置")
                    if body.id_token_profile:
                        client["claims_policy"] = claims_name
                        oidc.setdefault("claims_policies", {})[claims_name] = {"id_token": ["name", "email", "email_verified", "preferred_username"]}
                    else:
                        client.pop("claims_policy", None)
                        oidc.get("claims_policies", {}).pop(claims_name, None)
                        if not oidc.get("claims_policies"):
                            oidc.pop("claims_policies", None)
            else:
                if any(
                    not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,31}", m)
                    for m in body.bypass_methods
                ):
                    raise Problem("公开路径的 HTTP 方法需使用大写，例如 GET、HEAD")
                proxies = d["metadata"].setdefault("proxy_apps", {})
                app_id = body.id or "proxy:" + secrets.token_hex(8)
                if not body.creating and app_id not in proxies:
                    raise Problem("应用不存在", 404)
                domains = list(dict.fromkeys(body.domains))
                if not domains:
                    raise Problem("至少需要一个应用域名")
                for domain in domains:
                    if not re.fullmatch(
                        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                        domain,
                    ):
                        raise Problem(
                            "代理应用域名需为完整小写域名，不支持路径或通配符"
                        )
                # Never silently shadow an imported rule for the same exact domain.
                count = d["metadata"].get("managed_rule_count", 0)
                legacy = c.get("access_control", {}).get("rules", [])[count:]
                for rule in legacy:
                    old_domains = rule.get("domain", [])
                    if isinstance(old_domains, str):
                        old_domains = [old_domains]
                    if set(domains) & set(old_domains):
                        raise Problem(
                            "此域名已有手工代理规则，请在“代理规则”页管理；不要创建重复的代理应用"
                        )
                for other_id, other in proxies.items():
                    if other_id != app_id and set(domains) & set(other["domains"]):
                        raise Problem("域名已被其他代理应用使用")
                proxies[app_id] = {
                    "id": app_id,
                    "kind": "proxy",
                    "name": body.name,
                    "domains": domains,
                    "subjects": sorted(set(body.subjects)),
                    "access": body.access,
                    "mfa": body.mfa,
                    "advanced": False,
                    "bypass_resources": body.bypass_resources,
                    "bypass_methods": body.bypass_methods,
                }
                self.rebuild_proxy_rules(c, d["metadata"])
            d["config"] = dump_yaml(c)
            self.save(d, f"{'添加' if body.creating else '更新'}应用 {body.name}")

    def rebuild_proxy_rules(self, config, metadata):
        acl = config.setdefault("access_control", {})
        rules = acl.get("rules", [])
        legacy = list(rules[metadata.get("managed_rule_count", 0) :])
        managed = []
        for app in metadata.get("proxy_apps", {}).values():
            managed.extend(generated_rules(app))
        acl["rules"] = managed + legacy
        metadata["managed_rule_count"] = len(managed)

    def manual_rule_context(self, d):
        config = load_yaml(d["config"])
        acl = config.setdefault("access_control", {})
        rules = acl.setdefault("rules", [])
        offset = d["metadata"].get("managed_rule_count", 0)
        return config, acl, rules, offset

    def upsert_proxy_rule(self, body):
        with self.locked():
            d = self.draft()
            self.assert_version(d, body.version)
            config, acl, rules, offset = self.manual_rule_context(d)
            count = len(rules) - offset
            if body.index is not None and not 0 <= body.index < count:
                raise Problem("代理规则不存在，请刷新后重试", 404)
            if body.index is None and not 0 <= body.insert_before <= count:
                raise Problem("插入位置无效，请刷新后重试", 409)
            users = load_yaml(d["users"]).get("users", {})
            groups = set(d["metadata"].get("groups", [])) | {
                g for u in users.values() for g in u.get("groups", [])
            }
            permitted = {"user:" + n for n in users} | {"group:" + n for n in groups}
            original = rules[offset + body.index] if body.index is not None else None
            updated = edit_rule(original, body, permitted, Problem)
            if original is not None:
                if original == updated:
                    return
                rules[offset + body.index] = updated
                change = f"更新代理规则 #{offset + body.index + 1}"
            else:
                rules.insert(offset + body.insert_before, updated)
                change = f"新增代理规则 #{offset + body.insert_before + 1}"
            d["config"] = dump_yaml(config)
            self.save(d, change)

    def delete_proxy_rule(self, index, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            config, acl, rules, offset = self.manual_rule_context(d)
            if not 0 <= index < len(rules) - offset:
                raise Problem("代理规则不存在", 404)
            del rules[offset + index]
            if not rules:
                # ruamel corrupts commented empty block sequences and the following map.
                acl.pop("rules", None)
            d["config"] = dump_yaml(config)
            self.save(d, f"删除代理规则 #{offset + index + 1}")

    def move_proxy_rule(self, index, direction, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            config, acl, rules, offset = self.manual_rule_context(d)
            target = index + direction
            if (
                direction not in (-1, 1)
                or not 0 <= index < len(rules) - offset
                or not 0 <= target < len(rules) - offset
            ):
                raise Problem("不能将规则移出可编辑区域")
            old = rules.pop(offset + index)
            rules.insert(offset + target, old)
            d["config"] = dump_yaml(config)
            self.save(
                d, f"调整代理规则顺序 #{offset + index + 1} → #{offset + target + 1}"
            )

    def set_proxy_default(self, policy, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            config, acl, rules, offset = self.manual_rule_context(d)
            if acl.get("default_policy", "deny") == policy:
                return
            acl["default_policy"] = policy
            d["config"] = dump_yaml(config)
            self.save(d, f"更新代理默认策略为 {policy}")

    def check_policy(self, body):
        with self.locked():
            d = self.draft()
            self.assert_version(d, body.version)
            user = (
                load_yaml(d["users"]).get("users", {}).get(body.username)
                if body.username
                else None
            )
            if body.username and user is None:
                raise Problem("检查所选的用户不存在", 404)
            payload = {
                "url": body.url,
                "method": body.method,
                "ip": body.ip,
                "username": body.username,
                "groups": list(user.get("groups", [])) if user else [],
            }
            atomic_write(self.root / ".console-candidate.yml", d["config"])
            try:
                result = self.hook("check-policy", payload)
                result["disabled_user"] = bool(user and user.get("disabled", False))
                return result
            finally:
                (self.root / ".console-candidate.yml").unlink(missing_ok=True)

    def delete_app(self, app_id, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            c = load_yaml(d["config"])
            if app_id.startswith("oidc:"):
                oidc = c.get("identity_providers", {}).get("oidc", {})
                client_id = app_id[5:]
                clients = oidc.get("clients", [])
                if not any(str(x["client_id"]) == client_id for x in clients):
                    raise Problem("应用不存在", 404)
                if len(clients) == 1:
                    raise Problem("不能删除最后一个 OIDC 客户端；请先停用登录")
                oidc["clients"] = [
                    x for x in clients if str(x["client_id"]) != client_id
                ]
                pname = (
                    POLICY_PREFIX + hashlib.sha256(client_id.encode()).hexdigest()[:20]
                )
                oidc.get("authorization_policies", {}).pop(pname, None)
                claims_name = POLICY_PREFIX + "claims_" + hashlib.sha256(client_id.encode()).hexdigest()[:20]
                oidc.get("claims_policies", {}).pop(claims_name, None)
                if not oidc.get("claims_policies"):
                    oidc.pop("claims_policies", None)
                if not oidc.get("authorization_policies"):
                    oidc.pop("authorization_policies", None)
            else:
                # Keep a deny tombstone: deleting must not expose the domain via a permissive legacy default.
                app = d["metadata"].get("proxy_apps", {}).get(app_id)
                if not app:
                    raise Problem("应用不存在", 404)
                app["access"] = "deny"
                self.rebuild_proxy_rules(c, d["metadata"])
            d["config"] = dump_yaml(c)
            self.save(
                d,
                f"{'删除 OIDC 应用' if app_id.startswith('oidc:') else '停用代理应用'} {app_id}",
            )

    def preview(self):
        with self.locked():
            d = self.draft()
            out = []
            for name, a, b in [
                ("configuration.yml", d["base_config"], d["config"]),
                (self.users_path.name, d["base_users"], d["users"]),
            ]:
                ra, rb = (
                    dump_yaml(redact(load_yaml(a))),
                    dump_yaml(redact(load_yaml(b))),
                )
                diff = "".join(
                    difflib.unified_diff(
                        ra.splitlines(True),
                        rb.splitlines(True),
                        fromfile=name + " (当前)",
                        tofile=name + " (草稿)",
                    )
                )
                if diff:
                    out.append(diff)
            return {
                "diff": "\n".join(out) or "无可显示的字段差异（密码和 Secret 已隐藏）",
                "changes": d["changes"],
            }

    def discard(self, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            self.write_json("generation.json", d["version"] + 1)
            (self.state / "draft.json").unlink(missing_ok=True)

    def validate(self, d):
        atomic_write(self.root / ".console-candidate.yml", d["config"])
        try:
            return self.hook("validate")
        finally:
            (self.root / ".console-candidate.yml").unlink(missing_ok=True)

    def publish(self, version, check_only=False):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            config, users = self.read_live()
            if fingerprint(config, users) != d["base"]:
                raise Problem(
                    "线上文件已变化（可能是密码重置或手动修改），请先导出草稿差异，再丢弃草稿并重新导入。",
                    409,
                )
            result = self.validate(d)
            if check_only:
                return {
                    "message": "Authelia 配置校验通过",
                    "warnings": result.get("warnings", ""),
                }
            if not d["changes"]:
                raise Problem("没有待发布变更")
            latest_config, latest_users = self.read_live()
            if fingerprint(latest_config, latest_users) != d["base"]:
                raise Problem("线上文件在校验期间变化，发布已取消，请重新导入。", 409)
            before = {
                "id": secrets.token_hex(12),
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "summary": d["changes"],
                "config": config,
                "users": users,
                "metadata": self.read_json("metadata.json", {}),
            }
            self.write_json("transaction.json", before)
            wrote_config = wrote_users = False
            try:
                # Stop Authelia before replacing its password file, so its own
                # password-reset writer cannot race with the two-file commit.
                self.hook("stop")
                stopped_config, stopped_users = self.read_live()
                if fingerprint(stopped_config, stopped_users) != d["base"]:
                    before.update(config=stopped_config, users=stopped_users)
                    self.write_json("transaction.json", before)
                    raise Problem("停止服务期间文件已变化，发布已取消。", 409)
                atomic_write(self.config_path, d["config"])
                wrote_config = True
                # Detect an external password reset occurring while validation ran.
                if self.users_path.read_text() != users:
                    raise Problem("用户文件在发布期间被外部修改，发布已取消", 409)
                atomic_write(self.users_path, d["users"])
                wrote_users = True
                self.hook("restart")
                d["metadata"]["config_digest"] = hashlib.sha256(
                    d["config"].encode()
                ).hexdigest()
                self.write_json("metadata.json", d["metadata"])
                before["after"] = fingerprint(d["config"], d["users"])
                history = self.read_json("history.json", [])
                self.write_json("history.json", [before] + history[:19])
            except Exception as error:
                if not wrote_config:
                    before["config"] = self.config_path.read_text()
                if not wrote_users:
                    before["users"] = self.users_path.read_text()
                self.restore_files(before)
                try:
                    self.hook("restart")
                except Exception:
                    raise Problem(
                        "发布失败且自动恢复尚未通过健康检查；事务备份已保留，请检查 Authelia。",
                        503,
                    ) from error
                (self.state / "transaction.json").unlink(missing_ok=True)
                raise Problem("发布失败，已恢复原配置并通过健康检查。", 422) from error
            (self.state / "transaction.json").unlink(missing_ok=True)
            self.write_json("generation.json", d["version"] + 1)
            (self.state / "draft.json").unlink(missing_ok=True)
            return {
                "message": "配置已发布，Authelia 健康检查通过",
                "snapshot": before["id"],
            }

    def rollback(self, snapshot_id, version):
        with self.locked():
            d = self.draft()
            self.assert_version(d, version)
            if d["changes"]:
                raise Problem("请先发布或丢弃当前草稿，再恢复历史版本", 409)
            history = self.read_json("history.json", [])
            snap = next((x for x in history if x["id"] == snapshot_id), None)
            if not snap:
                raise Problem("历史版本不存在", 404)
            config, users = self.read_live()
            # Never silently replace a newer password reset or a later publication.
            if fingerprint(config, users) != snap.get("after"):
                raise Problem(
                    "当前配置或用户密码已在此版本后变化，不能直接回滚覆盖；请从最新快照恢复或手动合并。",
                    409,
                )
            d.update(
                config=snap["config"], users=snap["users"], metadata=snap["metadata"]
            )
            self.save(d, "恢复发布前版本 " + snapshot_id)
            return self.publish(d["version"])
