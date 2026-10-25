import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from authlib.integrations.starlette_client import OAuth
from authlib.jose import JsonWebKey, jwt
from fastapi.testclient import TestClient

from test_console import store
from app.main import create_app


@pytest.fixture
def oidc_env(monkeypatch):
    for key, value in {
        'AUTH_MODE':'oidc', 'BASE_PATH':'/console', 'OIDC_ISSUER':'https://id.example.com',
        'OIDC_CLIENT_ID':'console', 'OIDC_CLIENT_SECRET':'test-client-secret',
        'OIDC_ADMIN_USERS':'alice'
    }.items():monkeypatch.setenv(key,value)


class Provider:
    def __init__(self):
        self.key = JsonWebKey.generate_key('RSA',2048,is_private=True)
        self.query = None
        self.username = 'alice'
        self.subject = 'alice-stable-sub'
        self.overrides = {}
        self.info_sub = None
        self.token_calls = 0
        self.bad_signature = False
    def handle(self,request):
        if request.url.path == '/.well-known/openid-configuration':
            return httpx.Response(200,json={'issuer':'https://id.example.com',
                'authorization_endpoint':'https://id.example.com/authorize',
                'token_endpoint':'https://id.example.com/token',
                'userinfo_endpoint':'https://id.example.com/userinfo',
                'jwks_uri':'https://id.example.com/jwks',
                'id_token_signing_alg_values_supported':['RS256']})
        if request.url.path == '/jwks':return httpx.Response(200,json={'keys':[self.key.as_dict()]})
        if request.url.path == '/token':
            self.token_calls += 1
            data=parse_qs(request.content.decode())
            verifier=data['code_verifier'][0]
            challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            assert challenge==self.query['code_challenge'][0]
            assert request.headers['authorization'].startswith('Basic ')
            now=int(time.time())
            claims={'iss':'https://id.example.com','sub':self.subject,'aud':'console','iat':now,'exp':now+300,'nonce':self.query['nonce'][0],**self.overrides}
            signer=JsonWebKey.generate_key('RSA',2048,is_private=True) if self.bad_signature else self.key
            signed=jwt.encode({'alg':'RS256','kid':self.key.as_dict()['kid']},claims,signer).decode()
            return httpx.Response(200,json={'access_token':'synthetic-token','token_type':'Bearer','id_token':signed})
        if request.url.path == '/userinfo':
            return httpx.Response(200,json={'sub':self.info_sub or self.subject,'preferred_username':self.username})
        raise AssertionError(request.url)
    def client(self):
        oauth=OAuth()
        oauth.register('authelia',client_id='console',client_secret='test-client-secret',
            server_metadata_url='https://id.example.com/.well-known/openid-configuration',
            client_kwargs={'transport':httpx.MockTransport(self.handle),'scope':'openid profile email',
                           'code_challenge_method':'S256','token_endpoint_auth_method':'client_secret_basic'})
        return oauth.create_client('authelia')


def begin(client,provider):
    r=client.get('/auth/login',follow_redirects=False)
    assert r.status_code==302
    provider.query=parse_qs(urlsplit(r.headers['location']).query)
    assert provider.query['redirect_uri']==['https://console.example.com/console/auth/callback']
    assert provider.query['code_challenge_method']==['S256']
    return provider.query['state'][0]


def finish(client,state):
    return client.get('/auth/callback',params={'state':state,'code':'synthetic-code'},follow_redirects=False)


def make_client(store,provider):
    # External /console prefix is removed by Traefik before FastAPI sees the path.
    app=create_app(store=store,origin='https://console.example.com',oidc_client=provider.client())
    async def proxy(scope,receive,send):
        scope=dict(scope)
        if scope['type']=='http':
            scope['path']=scope['path'].removeprefix('/console')
            scope['raw_path']=scope['path'].encode()
        await app(scope,receive,send)
    return TestClient(proxy,base_url='https://console.example.com/console')


def test_oidc_owner_pkce_session_csrf_and_replay(store,oidc_env):
    p=Provider()
    # Keep the actual external cookie path while the test app uses stripped routes.
    with make_client(store,p) as c:
        state=begin(c,p)
        r=finish(c,state);assert r.status_code==303
        assert 'synthetic-token' not in r.headers.get('set-cookie','')
        r=c.get('/api/session');assert r.status_code==200 and r.json()['username']=='alice'
        csrf=r.json()['csrf']
        assert c.post('/api/groups',json={'version':0,'name':'new','members':[]},headers={'Origin':'https://console.example.com'}).status_code==403
        assert c.post('/api/groups',json={'version':0,'name':'new','members':[]},headers={'Origin':'https://console.example.com','X-CSRF-Token':csrf}).status_code==200
        # Replayed callback cannot exchange a second token once state is consumed.
        assert finish(c,state).status_code==400
        assert p.token_calls==1
        bindings=json.loads((store.state/'oidc-admins.json').read_text())
        assert bindings['alice']['sub']=='alice-stable-sub'


@pytest.mark.parametrize('alter', ['wrong-state','nonce','issuer','audience','expiry','other-user','userinfo-sub','signature'])
def test_oidc_rejects_invalid_proofs_and_unauthorized_accounts(store,oidc_env,alter):
    p=Provider()
    with make_client(store,p) as c:
        state=begin(c,p)
        if alter=='wrong-state':state='not-the-state'
        elif alter=='nonce':p.overrides['nonce']='wrong'
        elif alter=='issuer':p.overrides['iss']='https://wrong.example.com'
        elif alter=='audience':p.overrides['aud']='another-client'
        elif alter=='expiry':p.overrides['exp']=int(time.time())-1000
        elif alter=='other-user':p.username='bob'
        elif alter=='userinfo-sub':p.info_sub='another-sub'
        elif alter=='signature':p.bad_signature=True
        r=finish(c,state)
        assert r.status_code in (400,403)
        assert c.get('/api/state').status_code==401
        assert not (store.state/'oidc-admins.json').exists()


def test_oidc_mode_disables_password_and_untrusted_identity_headers(store,oidc_env):
    p=Provider()
    with make_client(store,p) as c:
        assert c.get('/api/auth-config').json()['mode']=='oidc'
        assert c.post('/api/login',json={'username':'admin','password':'anything'},headers={'Origin':'https://console.example.com'}).status_code==404
        assert c.get('/api/state',headers={'Remote-User':'alice','X-Remote-User':'alice'}).status_code==401


def test_oidc_subject_replacement_does_not_take_over_admin(store,oidc_env):
    (store.state/'oidc-admins.json').write_text(json.dumps({'alice':{'iss':'https://id.example.com','sub':'previous-sub'}}))
    p=Provider()
    with make_client(store,p) as c:
        state=begin(c,p)
        assert finish(c,state).status_code==403
        assert c.get('/api/state').status_code==401
