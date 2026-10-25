import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_console import store
from app.main import AppBody, PolicyCheck, ProxyRuleBody
from app.proxy_rules import subjects
from app.store import Problem, dump_yaml, load_yaml

spec = importlib.util.spec_from_file_location(
    "publication_agent", Path(__file__).parents[1] / "deploy" / "agent.py"
)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def edit_body(store, index=0, **updates):
    rule = store.view()["legacy_rules"][index]
    fields = {}
    for key in ("domain", "domain_regex", "resources", "methods", "networks"):
        value = rule.get(key, [])
        fields[key] = value if isinstance(value, list) else [value]
    fields.update(policy=rule["policy"], subject=subjects(rule.get("subject")))
    fields.update(updates)
    return ProxyRuleBody(version=store.view()["version"], index=index, **fields)


def test_rule_import_and_noop_edit_do_not_change_live_or_draft(store):
    before = store.read_live()
    rules = store.view()["proxy_rules"]
    assert rules[0]["position"] == 1
    assert rules[0]["rule"]["policy"] == "bypass"
    store.upsert_proxy_rule(edit_body(store))
    assert store.draft()["config"] == before[0]
    assert store.view()["changes"] == []
    assert store.read_live() == before


def test_edit_resource_preserves_unknown_query_conditions_and_order(store):
    config = load_yaml(store.config_path.read_text())
    config["access_control"]["rules"][0]["query"] = [
        [{"operator": "present", "key": "public"}]
    ]
    store.config_path.write_text(dump_yaml(config))
    original = copy.deepcopy(config["access_control"]["rules"])
    store.upsert_proxy_rule(
        edit_body(store, resources=["^/public/", "^/assets/"], methods=["GET", "HEAD"])
    )
    rules = load_yaml(store.draft()["config"])["access_control"]["rules"]
    assert rules[0]["query"] == original[0]["query"]
    assert rules[0]["methods"] == ["GET", "HEAD"]
    assert rules[0]["resources"] == ["^/public/", "^/assets/"]
    assert rules[1:] == original[1:]


def test_or_of_and_subjects_retains_exact_logic(store):
    config = load_yaml(store.config_path.read_text())
    config["access_control"]["rules"][1]["subject"] = [
        ["user:alice", "group:friends"],
        "user:bob",
    ]
    store.config_path.write_text(dump_yaml(config))
    store.upsert_proxy_rule(edit_body(store, index=1, methods=["POST"]))
    rule = load_yaml(store.draft()["config"])["access_control"]["rules"][1]
    assert rule["subject"] == [["user:alice", "group:friends"], "user:bob"]
    assert rule["methods"] == ["POST"]


def test_bypass_cannot_have_identity_conditions(store):
    with pytest.raises(Problem, match="免登录规则不能包含"):
        store.upsert_proxy_rule(edit_body(store, subject=[["user:alice"]]))
    assert not store.view()["changes"]


def test_empty_and_condition_and_lowercase_proxy_method_are_rejected(store):
    with pytest.raises(Problem, match="AND 分组"):
        store.upsert_proxy_rule(edit_body(store, index=1, subject=[["user:alice", ""]]))
    with pytest.raises(Problem, match="HTTP 方法需使用大写"):
        store.upsert_app(
            AppBody(
                version=0,
                kind="proxy",
                creating=True,
                name="Photos",
                domains=["photos.example.com"],
                access="all",
                bypass_resources=["^/assets/"],
                bypass_methods=["get"],
            )
        )
    assert not store.view()["changes"]


def test_create_reorder_and_delete_apply_only_to_draft(store):
    before = store.read_live()
    body = ProxyRuleBody(
        version=0,
        policy="bypass",
        domain=["photos.example.com"],
        resources=["^/assets/"],
        insert_before=0,
    )
    store.upsert_proxy_rule(body)
    assert store.view()["legacy_rules"][0]["domain"] == ["photos.example.com"]
    store.move_proxy_rule(0, 1, 1)
    assert store.view()["legacy_rules"][1]["domain"] == ["photos.example.com"]
    store.delete_proxy_rule(1, 2)
    assert (
        store.view()["legacy_rules"] == load_yaml(before[0])["access_control"]["rules"]
    )
    assert store.read_live() == before
    with pytest.raises(Problem, match="不能将规则移出"):
        store.move_proxy_rule(0, -1, 3)


def test_public_proxy_resources_precede_auth_and_are_removed_when_disabled(store):
    store.upsert_app(
        AppBody(
            version=0,
            kind="proxy",
            creating=True,
            name="Photos",
            domains=["photos.example.com"],
            access="restricted",
            subjects=["user:alice"],
            bypass_resources=["^/assets/", "^/share/"],
            bypass_methods=["GET", "HEAD"],
        )
    )
    view = store.view()
    assert view["managed_rule_count"] == 3
    generated = view["proxy_rules"][:3]
    assert [r["rule"]["policy"] for r in generated] == ["bypass", "two_factor", "deny"]
    assert all(r["managed"] and r["index"] is None for r in generated)
    assert generated[0]["rule"]["methods"] == ["GET", "HEAD"]
    assert "subject" not in generated[0]["rule"]
    app = next(a for a in view["applications"] if a["kind"] == "proxy")
    store.delete_app(app["id"], 1)
    view = store.view()
    assert view["managed_rule_count"] == 1
    assert view["proxy_rules"][0]["rule"]["policy"] == "deny"


def test_manual_reorder_preserves_generated_prefix_and_default_policy(store):
    store.upsert_app(
        AppBody(
            version=0,
            kind="proxy",
            creating=True,
            name="Photos",
            domains=["photos.example.com"],
            access="all",
        )
    )
    before = store.view()["proxy_rules"][0]["rule"]
    store.move_proxy_rule(0, 1, 1)
    assert store.view()["proxy_rules"][0]["rule"] == before
    store.set_proxy_default("two_factor", 2)
    assert store.view()["default_policy"] == "two_factor"
    assert store.view()["proxy_rules"][0]["rule"] == before


def test_policy_check_uses_draft_groups_and_cleans_candidate_on_failure(store):
    captured = {}

    def hook(action, payload):
        assert action == "check-policy"
        assert (store.root / ".console-candidate.yml").exists()
        captured.update(payload)
        raise Problem("native failure", 422)

    store.hook = hook
    with pytest.raises(Problem, match="native failure"):
        store.check_policy(
            PolicyCheck(
                version=0,
                url="https://photos.example.com/assets/app.css",
                username="alice",
            )
        )
    assert captured["groups"] == ["friends"]
    assert captured["username"] == "alice"
    assert not (store.root / ".console-candidate.yml").exists()
    assert store.view()["changes"] == []


def test_native_result_parser_distinguishes_anonymous_potential_matches():
    report = """Performing policy check for request.
  # Domain Resource Query Method Network Subject
  1 miss hit hit hit hit hit
~ 2 hit hit hit hit hit may
* 3 hit hit hit hit hit hit
The policy 'deny' from rule #2 will potentially be applied to this request. If not policy 'two_factor' from rule #3 will be.
"""
    parsed = agent.parse_policy_report(report)
    assert parsed["potential"] and parsed["policy"] is None
    assert len(parsed["rows"]) == 3
    assert parsed["rows"][1]["criteria"][-1] == "may"
    actual = agent.parse_policy_report(
        "* 2 hit hit hit hit hit hit\nThe policy 'bypass' from rule #2 will be applied to this request."
    )
    assert actual["policy"] == "bypass" and actual["position"] == 2
    default = agent.parse_policy_report(
        "The default policy 'one_factor' will be applied to this request."
    )
    assert default["policy"] == "one_factor" and default["position"] is None
    url_words = agent.parse_policy_report(
        "Performing policy check for request to 'https://example.com/potentially/The policy 'deny' from rule #1 will be applied'.\nThe policy 'bypass' from rule #2 will be applied to this request."
    )
    assert url_words["policy"] == "bypass" and not url_words["potential"]


def test_policy_check_arguments_are_validated_and_never_shell_commands():
    args = agent.policy_check_args(
        {
            "url": "https://photos.example.com/assets/app.css",
            "username": "alice",
            "groups": ["friends"],
            "method": "GET",
            "ip": "127.0.0.1",
        }
    )
    assert "--url=https://photos.example.com/assets/app.css" in args
    assert "--groups=friends" in args
    assert args[:3] == ["docker", "exec", agent.CONTAINER]
    for payload in (
        {"url": "file:///etc/passwd"},
        {"url": "https://foo.example.com/\n"},
        {"url": "https://foo.example.com", "method": "GET;id"},
        {"url": "https://foo.example.com", "ip": "invalid"},
    ):
        with pytest.raises(ValueError):
            agent.policy_check_args(payload)


def test_delete_last_commented_rule_keeps_draft_readable_and_accepts_new_app(store):
    original = store.config_path.read_text().replace('  rules:\n', '  rules:\n    # public exceptions\n', 1)
    store.config_path.write_text(original)
    for index in (1, 0):
        store.delete_proxy_rule(index, store.view()['version'])
    assert store.view()['legacy_rules'] == []
    store.upsert_app(AppBody(version=store.view()['version'],kind='proxy',creating=True,
                            name='Private',domains=['private.example.com'],
                            access='restricted',subjects=['user:alice']))
    assert store.view()['proxy_rules'][0]['rule']['subject'] == ['user:alice']
    assert store.config_path.read_text() == original


def test_native_default_policy_report_is_parsed():
    parsed = agent.parse_policy_report("The policy 'deny' from the default policy will be applied to this request.")
    assert parsed['policy'] == 'deny'
