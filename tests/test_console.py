import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import AppBody, GroupBody, UserBody, create_app
from app.store import HASHER, Problem, Store, dump_yaml, load_yaml


@pytest.fixture
def store(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "configuration.yml").write_text("""# preserved comment
theme: dark
authentication_backend:
  file:
    path: /config/users_database.yml
access_control:
  default_policy: one_factor
  rules:
    - domain: legacy.example.com
      resources: ['^/public/']
      policy: bypass
    - domain_regex: '^.*$'
      subject: ['group:blocked']
      policy: deny
identity_providers:
  oidc:
    hmac_secret: hidden-provider-secret
    clients:
      - client_id: existing
        client_name: Existing
        client_secret: hidden-client-secret
        authorization_policy: two_factor
        redirect_uris: ['oc://client.callback']
        grant_types: [authorization_code, refresh_token]
        token_endpoint_auth_method: client_secret_post
        scopes: [openid, groups, email, profile]
""")
    (config / "users_database.yml").write_text(
        dump_yaml(
            {
                "users": {
                    "alice": {
                        "displayname": "Alice",
                        "email": "alice@example.com",
                        "password": "hidden-password",
                        "groups": ["friends"],
                    },
                    "bob": {
                        "displayname": "Bob",
                        "email": "bob@example.com",
                        "password": "hidden-bob-password",
                        "groups": [],
                    },
                }
            }
        )
    )
    s = Store(config, tmp_path / "data", issuer="https://auth.example.com")
    return s


def app_body(store, **kwargs):
    return AppBody(
        version=store.view()["version"],
        kind="oidc",
        name="Existing",
        client_id="existing",
        id="oidc:existing",
        redirect_uris=["oc://client.callback"],
        access="restricted",
        subjects=["group:friends"],
        **kwargs,
    )


def fake_agent(store, fail_once=False):
    calls = []

    def hook(action):
        calls.append(action)
        if action == "validate":
            assert (store.root / ".console-candidate.yml").exists()
        if fail_once and action == "restart" and calls.count("restart") == 1:
            raise Problem("simulated health failure", 503)
        return {"ok": True}

    store.hook = hook
    return calls


def test_edit_keeps_existing_client_parameters_and_legacy_rules(store):
    before = load_yaml(store.config_path.read_text())
    store.upsert_app(app_body(store))
    after = load_yaml(store.draft()["config"])
    client = after["identity_providers"]["oidc"]["clients"][0]
    assert client["client_secret"] == "hidden-client-secret"
    assert client["grant_types"] == ["authorization_code", "refresh_token"]
    assert client["token_endpoint_auth_method"] == "client_secret_post"
    assert after["access_control"] == before["access_control"]
    assert store.draft()["config"].startswith("# preserved comment")
    policy = after["identity_providers"]["oidc"]["authorization_policies"][
        client["authorization_policy"]
    ]
    assert policy["default_policy"] == "deny"
    assert policy["rules"] == [{"policy": "two_factor", "subject": ["group:friends"]}]
    assert store.view()["applications"][0]["access"] == "restricted"


def test_secrets_absent_from_api_state_and_preview(store):
    store.upsert_app(app_body(store))
    data = json.dumps({"state": store.view(), "preview": store.preview()})
    assert "hidden-client-secret" not in data
    assert "hidden-provider-secret" not in data
    assert "hidden-password" not in data


def test_group_membership_and_hashed_new_password(store):
    store.group("photos", ["alice"], 0)
    store.upsert_user(
        UserBody(
            version=1,
            username="carol",
            displayname="Carol",
            email="carol@example.com",
            password="correct-horse-forest",
            groups=["photos"],
            creating=True,
        )
    )
    users = load_yaml(store.draft()["users"])["users"]
    assert "photos" in users["alice"]["groups"]
    assert HASHER.verify(users["carol"]["password"], "correct-horse-forest")
    assert "password" not in store.view()["users"][0]


def test_optimistic_draft_and_external_password_reset(store):
    store.group("photos", [], 0)
    with pytest.raises(Problem, match="其他页面"):
        store.group("second", [], 0)
    current = store.users_path.read_text()
    store.users_path.write_text(
        current.replace("hidden-password", "new-user-reset-hash")
    )
    assert store.view()["conflict"]
    with pytest.raises(Problem, match="线上文件已变化"):
        store.publish(1)
    assert "new-user-reset-hash" in store.users_path.read_text()


def test_publish_failure_restores_original_files(store):
    before = store.read_live()
    store.group("photos", ["alice"], 0)
    calls = fake_agent(store, fail_once=True)
    with pytest.raises(Problem, match="已恢复原配置"):
        store.publish(1)
    assert store.read_live() == before
    assert calls == ["validate", "stop", "restart", "restart"]
    assert not (store.state / "transaction.json").exists()
    assert store.view()["changes"]


def test_successful_publish_and_rollback(store):
    before = store.read_live()
    store.group("photos", ["alice"], 0)
    fake_agent(store)
    result = store.publish(1)
    assert store.view()["changes"] == []
    assert (
        "photos" in load_yaml(store.users_path.read_text())["users"]["alice"]["groups"]
    )
    assert (store.state / "history.json").stat().st_mode & 0o777 == 0o600
    store.rollback(result["snapshot"], store.view()["version"])
    assert store.read_live() == before


def test_rollback_cannot_overwrite_newer_password_reset(store):
    store.group("photos", ["alice"], 0)
    fake_agent(store)
    result = store.publish(1)
    store.users_path.write_text(
        store.users_path.read_text().replace("hidden-password", "new-user-reset-hash")
    )
    with pytest.raises(Problem, match="密码已在此版本后变化"):
        store.rollback(result["snapshot"], store.view()["version"])
    assert "new-user-reset-hash" in store.users_path.read_text()


def test_new_proxy_rules_allow_selected_then_deny_everyone_else(store):
    legacy = load_yaml(store.draft()["config"])["access_control"]["rules"]
    store.upsert_app(
        AppBody(
            version=0,
            kind="proxy",
            creating=True,
            name="Photos",
            domains=["photos.example.com"],
            subjects=["user:alice"],
            access="restricted",
        )
    )
    c = load_yaml(store.draft()["config"])
    assert c["access_control"]["rules"][:2] == [
        {
            "domain": ["photos.example.com"],
            "policy": "two_factor",
            "subject": ["user:alice"],
        },
        {"domain": ["photos.example.com"], "policy": "deny"},
    ]
    assert c["access_control"]["rules"][2:] == legacy
    app = next(a for a in store.view()["applications"] if a["kind"] == "proxy")
    store.delete_app(app["id"], 1)
    assert (
        load_yaml(store.draft()["config"])["access_control"]["rules"][0]["policy"]
        == "deny"
    )


def test_legacy_exact_domain_cannot_be_shadowed(store):
    with pytest.raises(Problem, match="已有手工代理规则"):
        store.upsert_app(
            AppBody(
                version=0,
                kind="proxy",
                creating=True,
                name="Legacy",
                domains=["legacy.example.com"],
                access="all",
            )
        )


def test_custom_policy_not_silently_flattened(store):
    c = load_yaml(store.config_path.read_text())
    oidc = c["identity_providers"]["oidc"]
    oidc["clients"][0]["authorization_policy"] = "network_policy"
    oidc["authorization_policies"] = {
        "network_policy": {
            "default_policy": "deny",
            "rules": [
                {
                    "policy": "two_factor",
                    "networks": ["10.0.0.0/8"],
                    "subject": ["group:friends"],
                }
            ],
        }
    }
    store.config_path.write_text(dump_yaml(c))
    assert store.view()["applications"][0]["advanced"]
    with pytest.raises(Problem, match="高级策略"):
        store.upsert_app(app_body(store))


def test_change_during_validator_is_not_overwritten(store):
    store.group("photos", [], 0)

    def hook(action):
        store.users_path.write_text(
            store.users_path.read_text().replace(
                "hidden-password", "reset-during-validation"
            )
        )
        return {}

    store.hook = hook
    with pytest.raises(Problem, match="校验期间变化"):
        store.publish(1)
    assert "reset-during-validation" in store.users_path.read_text()


def test_authentication_csrf_origin_and_secret_redaction(store, monkeypatch):
    monkeypatch.delenv("BASE_PATH", raising=False)
    app = create_app(
        store, HASHER.hash("this-is-test-admin-password"), "http://testserver"
    )
    with TestClient(app) as client:
        assert client.get("/api/state").status_code == 401
        assert (
            client.post(
                "/api/login",
                json={"username": "admin", "password": "this-is-test-admin-password"},
            ).status_code
            == 403
        )
        login = client.post(
            "/api/login",
            headers={"origin": "http://testserver"},
            json={"username": "admin", "password": "this-is-test-admin-password"},
        )
        assert login.status_code == 200
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "SameSite=strict" in login.headers["set-cookie"]
        assert client.get("/api/state").status_code == 200
        assert "hidden-client-secret" not in client.get("/api/state").text
        assert (
            client.post(
                "/api/groups",
                headers={"origin": "http://testserver"},
                json={"name": "test", "members": [], "version": 0},
            ).status_code
            == 403
        )
        headers = {"origin": "http://testserver", "x-csrf-token": login.json()["csrf"]}
        assert (
            client.post(
                "/api/groups",
                headers=headers,
                json={"name": "test", "members": [], "version": 0},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/groups",
                headers={**headers, "origin": "http://evil.invalid"},
                json={"name": "x", "members": [], "version": 1},
            ).status_code
            == 403
        )
        assert client.post("/api/logout", headers=headers, json={}).status_code == 200
        assert client.get("/api/state").status_code == 401


def test_new_confidential_client_requires_secret_and_preserves_mobile_redirect(store):
    body = AppBody(
        version=0,
        kind="oidc",
        creating=True,
        name="Mobile",
        client_id="new-mobile",
        public=True,
        redirect_uris=["oc://mobile.auth"],
        access="restricted",
        subjects=["user:alice"],
    )
    store.upsert_app(body)
    client = load_yaml(store.draft()["config"])["identity_providers"]["oidc"][
        "clients"
    ][-1]
    assert client["require_pkce"] and client["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in client
    assert client["redirect_uris"] == ["oc://mobile.auth"]


def test_recovery_of_interrupted_transaction(store):
    before_config, before_users = store.read_live()
    store.write_json(
        "transaction.json",
        {"config": before_config, "users": before_users, "metadata": {}},
    )
    store.config_path.write_text("broken: half-published\n")
    store.hooks_socket = "test-agent"
    calls = fake_agent(store)
    store.recover()
    assert store.read_live() == (before_config, before_users)
    assert calls == ["stop", "restart"]
    assert not (store.state / "transaction.json").exists()


def test_unquoted_authelia_secret_template_is_preserved(store):
    text = store.config_path.read_text()
    expression = '{{ secret "/secrets/private.pem" | mindent 10 "|" | msquote }}'
    text += "\ncustom_signing_key: " + expression + "\n"
    store.config_path.write_text(text)
    store.upsert_app(app_body(store))
    assert "custom_signing_key: " + expression in store.draft()["config"]
    assert "msquote: null" not in store.draft()["config"]


def test_old_browser_revision_invalid_after_publish_and_discard(store):
    store.group("photos", [], 0)
    fake_agent(store)
    store.publish(1)
    with pytest.raises(Problem, match="其他页面"):
        store.group("stale-browser", [], 0)
    current = store.view()["version"]
    store.group("draft-group", [], current)
    store.discard(store.view()["version"])
    with pytest.raises(Problem, match="其他页面"):
        store.group("stale-again", [], current)


def test_reset_during_service_stop_is_preserved_and_publication_cancelled(store):
    store.group("photos", [], 0)
    before_config = store.config_path.read_text()
    calls = []

    def hook(action):
        calls.append(action)
        if action == "stop":
            store.users_path.write_text(
                store.users_path.read_text().replace(
                    "hidden-password", "reset-before-stop-completed"
                )
            )
        return {}

    store.hook = hook
    with pytest.raises(Problem, match="已恢复原配置"):
        store.publish(1)
    assert "reset-before-stop-completed" in store.users_path.read_text()
    assert store.config_path.read_text() == before_config
    assert calls == ["validate", "stop", "restart"]


def test_oidc_id_token_profile_is_explicit_and_round_trips(store):
    body=app_body(store,scopes=['openid','profile','email'],id_token_profile=True)
    store.upsert_app(body)
    assert store.view()['applications'][0]['id_token_profile'] is True
    config=load_yaml(store.draft()['config']);oidc=config['identity_providers']['oidc']
    client=oidc['clients'][0]
    assert oidc['claims_policies'][client['claims_policy']]['id_token']==['name','email','email_verified','preferred_username']
    body.version=store.view()['version'];body.id_token_profile=False
    store.upsert_app(body)
    assert store.view()['applications'][0]['id_token_profile'] is False
    assert 'claims_policies' not in load_yaml(store.draft()['config'])['identity_providers']['oidc']


def test_custom_claims_policy_is_preserved_and_not_silently_replaced(store):
    config=load_yaml(store.config_path.read_text())
    config['identity_providers']['oidc']['clients'][0]['claims_policy']='custom'
    config['identity_providers']['oidc']['claims_policies']={'custom':{'id_token':['email']}}
    store.config_path.write_text(dump_yaml(config))
    assert store.view()['applications'][0]['id_token_profile'] is None
    store.upsert_app(app_body(store))
    assert load_yaml(store.draft()['config'])['identity_providers']['oidc']['clients'][0]['claims_policy']=='custom'
    with pytest.raises(Problem,match='自定义 Claims'):
        store.upsert_app(app_body(store,id_token_profile=True,scopes=['openid','profile','email']))
