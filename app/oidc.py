"""OIDC protocol handling and a persistent issuer/subject administrator binding."""
import fcntl
import json
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from .store import Problem, atomic_write


class OIDCLogin:
    def __init__(self, state_dir, issuer, client_id, client_secret, users, client=None):
        parsed = urlsplit(issuer)
        if parsed.scheme != 'https' or not parsed.netloc or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise RuntimeError('OIDC_ISSUER must be an HTTPS issuer URL')
        if not client_id or not client_secret or not users:
            raise RuntimeError('OIDC requires a client ID, secret and explicit administrator usernames')
        self.issuer = issuer.rstrip('/')
        self.users = set(users)
        self.state_dir = state_dir
        if client is None:
            oauth = OAuth()
            oauth.register('authelia', client_id=client_id, client_secret=client_secret,
                           server_metadata_url=self.issuer+'/.well-known/openid-configuration',
                           client_kwargs={'scope':'openid profile email',
                                          'code_challenge_method':'S256',
                                          'token_endpoint_auth_method':'client_secret_basic'})
            client = oauth.create_client('authelia')
        self.client = client

    async def begin(self, request, redirect_uri):
        metadata = await self.client.load_server_metadata()
        if metadata.get('issuer') != self.issuer:
            raise Problem('身份提供方的 issuer 与配置不一致', 502)
        return await self.client.authorize_redirect(request, redirect_uri)

    async def finish(self, request):
        # Authlib validates authorization state, PKCE, signature, issuer, audience,
        # expiry and nonce before exposing the ID-token claims.
        token = await self.client.authorize_access_token(request)
        claims = token.get('userinfo')
        if not claims or claims.get('iss') != self.issuer or not claims.get('sub'):
            raise Problem('身份提供方没有返回有效的身份凭据', 403)
        info = await self.client.userinfo(token=token)
        if not info or info.get('sub') != claims['sub']:
            raise Problem('用户资料与身份凭据不匹配', 403)
        username = info.get('preferred_username')
        if username not in self.users:
            raise Problem('此账号没有工作台管理权限', 403)
        identity = {'iss': self.issuer, 'sub': claims['sub']}
        # Bind once after provider and local allowlists succeed. A later account
        # rename/replacement cannot silently take over this administrator binding.
        with open(self.state_dir / '.oidc-binding.lock', 'a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = self.state_dir / 'oidc-admins.json'
            bindings = json.loads(path.read_text()) if path.exists() else {}
            if username in bindings and bindings[username] != identity:
                raise Problem('管理员身份绑定已变化，请通过服务器核对后恢复', 403)
            if username not in bindings:
                bindings[username] = identity
                atomic_write(path, json.dumps(bindings))
        return {'username':username, 'sub':claims['sub'], 'auth':'oidc'}
