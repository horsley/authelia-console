"""Ordered ForwardAuth rules: preserve conditions, edit without flattening semantics."""

import copy
import re

POLICIES = {"bypass", "deny", "one_factor", "two_factor"}
EDITABLE_FIELDS = {
    "domain",
    "domain_regex",
    "resources",
    "methods",
    "networks",
    "subject",
    "policy",
}


def as_list(value):
    return list(value) if isinstance(value, list) else [value] if value else []


def subjects(value):
    """First level is OR; every inner list is AND. Never flatten an inner list."""
    return [as_list(item) for item in as_list(value)]


def edit_rule(original, body, allowed_subjects, problem):
    rule = copy.deepcopy(original) if original else {}
    if not body.domain and not body.domain_regex:
        raise problem("请至少填写一个域名或域名正则")
    if body.policy == "bypass" and body.subject:
        raise problem("免登录规则不能包含用户或组条件；识别用户身份需要先登录")
    for domain in body.domain:
        host = domain[2:] if domain.startswith("*.") else domain
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
            host,
        ):
            # Preserve legacy wildcard forms when unrelated fields are edited.
            if domain not in as_list(rule.get("domain")):
                raise problem("域名格式无效；可填写完整域名或 *.example.com")
    for method in body.methods:
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,31}", method):
            raise problem("HTTP 方法需使用大写，例如 GET、HEAD、POST、PROPFIND")
    old_subjects = subjects(rule.get("subject"))
    existing = {s for group in old_subjects for s in group}
    for group in body.subject:
        if not group or any(not s for s in group):
            raise problem("用户条件不能包含空的 AND 分组")
        for subject in group:
            if subject not in allowed_subjects | existing:
                raise problem("用户条件引用了不存在的用户或组，请先创建相应用户或组")
    rule["policy"] = body.policy
    for key in ("domain", "domain_regex", "resources", "methods", "networks"):
        values = getattr(body, key)
        if as_list(rule.get(key)) == values:
            continue  # Retain scalar/list style, quotes, and comments on no-op edits.
        if values:
            rule[key] = values
        else:
            rule.pop(key, None)
    if old_subjects != body.subject:
        if body.subject:
            rule["subject"] = [g[0] if len(g) == 1 else g for g in body.subject]
        else:
            rule.pop("subject", None)
    return rule


def generated_rules(app):
    """Public resource exceptions precede authentication and fallback denial."""
    domain = app["domains"]
    rules = []
    if app["access"] != "deny":
        if app.get("bypass_resources"):
            public = {
                "domain": domain,
                "resources": app["bypass_resources"],
                "policy": "bypass",
            }
            if app.get("bypass_methods"):
                public["methods"] = app["bypass_methods"]
            rules.append(public)
        auth = {
            "domain": domain,
            "policy": "two_factor" if app["mfa"] else "one_factor",
        }
        if app["access"] == "restricted":
            auth["subject"] = app["subjects"]
        rules.append(auth)
    if app["access"] != "all":
        rules.append({"domain": domain, "policy": "deny"})
    return rules
