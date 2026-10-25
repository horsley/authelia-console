#!/usr/bin/env python3
"""Host-side narrow agent. Never exposes Docker's socket or a shell to the UI."""

import http.server
import json
import os
import re
import ipaddress
import socketserver
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

SOCKET = os.environ.get("AGENT_SOCKET", "/run/authelia-console/agent.sock")
CONTAINER = os.environ.get("AUTHELIA_CONTAINER", "authelia")
CANDIDATE = "/config/.console-candidate.yml"


def run(args, timeout=40):
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )


def policy_check_args(payload):
    if not isinstance(payload, dict):
        raise ValueError("invalid request")
    url = payload.get("url", "")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 for c in url):
        raise ValueError("invalid URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("invalid URL")
    method = payload.get("method", "GET")
    if not isinstance(method, str) or not re.fullmatch(
        r"[A-Z][A-Z0-9_-]{0,31}", method
    ):
        raise ValueError("invalid method")
    username = payload.get("username", "")
    groups = payload.get("groups", [])
    if (
        not isinstance(username, str)
        or len(username) > 80
        or any(ord(c) < 32 for c in username)
    ):
        raise ValueError("invalid username")
    if (
        not isinstance(groups, list)
        or len(groups) > 200
        or any(
            not isinstance(g, str)
            or not g
            or len(g) > 128
            or "," in g
            or any(ord(c) < 32 for c in g)
            for g in groups
        )
    ):
        raise ValueError("invalid groups")
    ip = payload.get("ip", "")
    if ip:
        ipaddress.ip_address(ip)
    args = [
        "docker",
        "exec",
        CONTAINER,
        "authelia",
        "access-control",
        "check-policy",
        "--config",
        CANDIDATE,
        "--url=" + url,
        "--method=" + method,
        "--verbose",
    ]
    if username:
        args.append("--username=" + username)
    if groups:
        args.append("--groups=" + ",".join(groups))
    if ip:
        args.append("--ip=" + ip)
    return args


def parse_policy_report(output):
    start = output.find("Performing policy check")
    if start >= 0:
        output = output[start:]
    match = re.search(
        r"^The (?:default )?policy '(bypass|deny|one_factor|two_factor)'(?: from rule #(\d+)| from the default policy)? will be applied",
        output,
        re.I | re.M,
    )
    rows = []
    for line in output.splitlines():
        row = re.fullmatch(
            r"\s*([*~]?)\s*(\d+)\s+(hit|miss|may)\s+(hit|miss|may)\s+(hit|miss|may)\s+(hit|miss|may)\s+(hit|miss|may)\s+(hit|miss|may)\s*",
            line,
        )
        if row:
            rows.append(
                {
                    "marker": row.group(1),
                    "position": int(row.group(2)),
                    "criteria": list(row.groups()[2:]),
                }
            )
    return {
        "policy": match.group(1).lower() if match else None,
        "position": int(match.group(2)) if match and match.group(2) else None,
        "potential": bool(
            re.search(r"^The policy .* will potentially be applied", output, re.M)
        ),
        "rows": rows,
        "report": output[-16000:],
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        status, result = 200, {"ok": True}
        try:
            if self.path == "/validate":
                r = run(
                    [
                        "docker",
                        "exec",
                        CONTAINER,
                        "authelia",
                        "config",
                        "validate",
                        "--config",
                        CANDIDATE,
                    ]
                )
                if r.returncode:
                    status, result = (
                        422,
                        {
                            "error": "Authelia 拒绝候选配置，请检查回调地址、OIDC 配置和授权规则。详细校验结果可在主机手动运行校验命令查看。"
                        },
                    )
                else:
                    result["warnings"] = (
                        "现有配置包含兼容性警告"
                        if "warning" in (r.stdout + r.stderr).lower()
                        else ""
                    )
            elif self.path == "/check-policy":
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 32768:
                    raise ValueError("invalid length")
                payload = json.loads(self.rfile.read(length))
                r = run(policy_check_args(payload), timeout=25)
                if r.returncode:
                    status, result = (
                        422,
                        {"error": "原生策略检查失败，请检查请求参数并先校验草稿配置。"},
                    )
                else:
                    result = parse_policy_report(r.stdout)
            elif self.path == "/stop":
                r = run(["docker", "stop", "--time", "10", CONTAINER], timeout=35)
                if r.returncode:
                    raise RuntimeError("stop failed")
            elif self.path == "/restart":
                r = run(["docker", "restart", "--time", "10", CONTAINER], timeout=35)
                if r.returncode:
                    raise RuntimeError("restart failed")
                for _ in range(45):
                    r = run(
                        [
                            "docker",
                            "exec",
                            CONTAINER,
                            "wget",
                            "-qO-",
                            "http://127.0.0.1:9091/api/health",
                        ],
                        timeout=5,
                    )
                    try:
                        if (
                            r.returncode == 0
                            and json.loads(r.stdout).get("status") == "OK"
                        ):
                            break
                    except ValueError:
                        pass
                    time.sleep(1)
                else:
                    raise RuntimeError("health check failed")
            else:
                status, result = 404, {"error": "Unknown operation"}
        except (ValueError, TypeError):
            status, result = (
                400,
                {
                    "error": "请求检查参数无效，请使用完整 HTTP(S) URL、大写方法和有效 IP 地址。"
                },
            )
        except Exception:
            status, result = 503, {"error": "Authelia 未能完成重启或健康检查"}
        data = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(socketserver.UnixStreamServer):
    allow_reuse_address = True


if __name__ == "__main__":
    Path(SOCKET).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        Path(SOCKET).unlink()
    except FileNotFoundError:
        pass
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o600)
        server.serve_forever()
