"""Generate a console admin password hash without exposing plaintext arguments."""

import getpass
from .store import HASHER

if __name__ == "__main__":
    password = getpass.getpass("管理员密码（至少 16 字符）: ")
    if len(password) < 16:
        raise SystemExit("密码至少 16 字符")
    if password != getpass.getpass("再次输入: "):
        raise SystemExit("两次输入不一致")
    print(HASHER.hash(password))
