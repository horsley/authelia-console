# Authelia Console

[![CI](https://github.com/horsley/authelia-console/actions/workflows/test.yml/badge.svg)](https://github.com/horsley/authelia-console/actions/workflows/test.yml)

A self-hosted administration UI for Authelia file users, groups, OIDC clients, and ForwardAuth policies. Community project; not an official Authelia product.

## 功能

- 文件用户与用户组管理。
- OIDC 客户端、用户/组授权、MFA、PKCE 和 ID Token 资料兼容选项。
- ForwardAuth 应用、公开路径、HTTP 方法限制、手工规则及排序。
- 原生请求策略检查、脱敏变更预览、配置校验和发布回滚。
- 通过 Authelia 自身的 OIDC 登录工作台，支持管理员白名单及 issuer/sub 绑定。

界面目前主要使用中文。仅支持 Authelia 文件用户后端，不能替代目标应用内部的文件、空间或业务权限管理。

## 安全与数据边界

仓库只包含源码、示例和合成测试数据。运行实例的 Authelia 配置、用户文件、密码哈希、OIDC Secret、签名密钥、会话密钥、草稿和发布历史都必须留在私有存储中，不能提交到 Git。

工作台能够管理认证配置，应只授权可信管理员。OIDC 模式使用授权码、PKCE S256、state/nonce、签名、issuer/audience 和有效期检查；应用再次核对管理员白名单，并持久绑定首次验证后的 issuer/sub。不会信任客户端传入的 Remote-User 等身份头。

OIDC 临时 cookie 有效期 10 分钟；工作台会话有效期 8 小时，使用 Secure、HttpOnly 和 SameSite，写入 API 还要求 Origin/Host/CSRF 校验。身份提供方的 token 不会写入工作台会话 cookie。退出工作台不会自动退出提供方的 SSO 会话。

## 准备 OIDC 客户端

先在已有 Authelia 配置中注册机密客户端：

- Client ID：例如 `authelia-console`。
- Callback：`https://auth.example.com/console/auth/callback`。
- Scopes：openid、profile、email。
- 要求 PKCE S256，仅授权选定管理员，并要求 MFA。

将 Client Secret 保存在私有环境变量中，Authelia 侧保存其哈希。将工作台的 `OIDC_ADMIN_USERS` 设为明确的用户名列表，例如 `alice`，不是用户组名。

首次部署存在引导依赖：必须先准备可用的 Authelia 和 OIDC 客户端，再启用 Console 自身的 OIDC 登录。

## Dokploy 部署

使用仓库根目录的 `compose.dokploy.yml`，Compose Type 选择 Docker Compose。GitHub 源选择自己的仓库与 `main` 分支，Compose Path 为 `./compose.dokploy.yml`。

将以下变量放在 **Dokploy Environment** 中，不能写进仓库：

```dotenv
PUBLIC_ORIGIN=https://auth.example.com
OIDC_ISSUER=https://auth.example.com
OIDC_CLIENT_ID=authelia-console
OIDC_CLIENT_SECRET=<your-client-secret>
OIDC_ADMIN_USERS=alice
AUTHELIA_CONFIG_DIR=/data/authelia/config
CONSOLE_STATE_DIR=/opt/authelia-console/data
AGENT_SOCKET_DIR=/run/authelia-console
```

必须沿用已有实例的数据目录、用户配置目录和 agent socket 目录。Git checkout 的目录不能作为生产数据目录；重新拉取源码不能清空运行数据。

添加 Dokploy 域名：

- Host：例如 auth.example.com，Path：`/console`。
- Service：console，Port：8096，HTTPS。
- 关闭 Dokploy 内置 Strip Path。
- Middlewares 按顺序填写 `console-oidc-slash`、`console-oidc-prefix`，二者在 Compose 中定义。

不要给工作台的 OIDC 登录和回调额外添加会造成循环依赖的 ForwardAuth。业务端口仅加入 Docker 网络，不发布到宿主公网。

构建使用仓库中的 Dockerfile。默认 PyPI 源为腾讯云 HTTPS 镜像，可用构建参数 `PIP_INDEX_URL` 更换，不关闭证书校验。

### 自动部署

启用 Dokploy 的 GitHub 集成和 Auto Deploy，监听 `main` 的 push。GitHub App 必须能访问该仓库并发送 webhook。仓库的 CI 执行测试和 JS 语法检查；原生 push 自动部署与 CI 独立，并不等待 CI 完成。

拥有部署分支写权限的人可以改变工作台运行代码，因此仓库写权限应当按认证管理权限对待。Fork 和其他分支不会触发该实例的部署。

Web 应用会随 GitHub push 自动重建。下面的**宿主发布代理**及 systemd unit 不会由容器自动替换；涉及它们的升级应单独核对并同步，避免让 Web 应用获得任意宿主代码执行权限。

## 受限制的发布代理

在 Authelia 所在宿主上安装 `deploy/agent.py` 和 `deploy/authelia-console-agent.service`。示例 unit 的源码路径为 `/opt/authelia-console/deploy/agent.py`，可按实际安装路径调整；默认操作容器名 `authelia`。

代理只提供校验、原生命中检查及指定 Authelia 容器的停止/重启等有限操作。Console 不挂载 Docker socket。宿主代理兼容 Python 3.6，Web 容器使用 Python 3.12。

发布会先校验并保存快照，再停止 Authelia、重新核对文件、原子写入并启动检查；失败恢复原配置。外部配置或密码写入会触发草稿冲突保护。现有 Go secret 模板会经过保护后再进行 YAML 解析，避免破坏模板。

配置发布会重启 Authelia。使用内存 SSO 会话时，这可能要求重新登录；工作台自己的会话与提供方会话分开管理。

## 普通 Compose 部署

也可复制 `.env.example` 为私有 `.env`，填写真实值，然后使用 `compose.yml`。该方式把 8096 仅绑定到宿主 loopback，供已有反向代理使用。`deploy/traefik-console.yml` 提供使用示例域名的路由参考，部署前须修改。

## 接入应用

在“应用与访问”添加客户端，填写回调、Scopes、允许用户/组与 MFA。Secret 只在创建时显示，保存后仅保留哈希，必须先复制到目标应用。

现代客户端要求 PKCE；不支持 PKCE 的机密服务可以在创建时关闭。直接读取 ID Token 用户资料的应用可勾选对应兼容选项，需 profile/email scopes。现有自定义 Claims 策略会保留，不猜测或覆盖其语义。

代理应用按公开路径豁免、身份授权和拒绝兜底生成规则；未指定用户的原生 CLI 检查可能报告潜在匹配。只有已把入口接到 ForwardAuth 的路由才会使用这些规则。目标应用采用原生 OIDC 后，公开分享与私有 API 应由目标应用自己区分。

## 恢复

保留私有数据目录的完整备份，包括 metadata、历史/事务、session-key 和 oidc-admins.json。恢复前停止写入，不在线覆盖数据。

首先通过 SSH 恢复可用的 Authelia 配置。只有显式配置 `AUTH_MODE=password`、`ADMIN_USERNAME` 和 `ADMIN_PASSWORD_HASH` 时才启用应急密码模式；OIDC 模式中的密码端点返回 404，没有自动回退。恢复后切回 OIDC 并移除应急凭据。确认 issuer/sub 发生合法变更后，才可在服务器端修复管理员绑定。

## 开发与测试

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest==9.1.1
python -m pytest -q
node --check app/static/app.js
```

当前测试集包含 43 项测试。测试使用临时文件和合成 OIDC 提供方，包含真实签名 token、PKCE、签名/issuer/audience/nonce/state/过期拒绝、白名单、主体绑定、CSRF、配置保留及发布回滚，不需要生产凭据。

## License

MIT
