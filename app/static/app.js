"use strict";
const root = document.querySelector("#root"),
  modal = document.querySelector("#modal"),
  mc = document.querySelector("#modal-content");
const base = new URL(".", location.href).pathname.replace(/\/$/, "");
let authConfig = {mode: "password"};
let currentUsername = "admin";
let state,
  csrf = "",
  page = "applications",
  filter = "all",
  query = "",
  busy = false;
const e = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const attr = e;
const icons = {
  applications: "◈",
  rules: "≋",
  users: "♙",
  groups: "⊞",
  history: "↺",
};
const titles = {
  applications: "应用与访问",
  rules: "代理规则",
  users: "用户",
  groups: "用户组",
  history: "发布记录",
};
const subs = {
  applications: "把每个应用，交给合适的人。",
  rules: "让公开资源直接通行，让受保护的页面按规则登录。",
  users: "管理账号、身份与应用访问范围。",
  groups: "通过分组，让日常授权更简单。",
  history: "每一次配置发布，都有迹可循。",
};
function toast(text, error = false) {
  const t = document.querySelector("#toast");
  t.textContent = text;
  t.className = "show" + (error ? " error" : "");
  clearTimeout(t.timer);
  t.timer = setTimeout(() => (t.className = ""), 5500);
}
async function api(path, method = "GET", body) {
  const r = await fetch(base + "/api/" + path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const d = await r
    .json()
    .catch(() => ({ error: "服务器返回了无法读取的响应" }));
  if (!r.ok) {
    if (r.status === 401 && path !== "login") {
      modal.close();
      loginPage();
    }
    throw Error(
      d.error || (d.detail ? "输入内容不符合要求，请检查表单" : "请求失败"),
    );
  }
  return d;
}
async function refresh() {
  state = await api("state");
  render();
}
function loginPage() {
  if (authConfig.mode === "oidc") {
    root.innerHTML = `<div class="login-layout"><aside class="login-aside"><div class="brand"><img src="${base}/assets/favicon.svg" alt=""><div><strong>Authelia Console</strong><small>IDENTITY, SIMPLIFIED</small></div></div><div class="login-statement"><div class="eyebrow">YOUR PRIVATE ACCESS DESK</div><h1>一个身份，<br>管理你的应用。</h1><p>通过 Authelia 验证身份，进入你的访问管理工作台。</p></div></aside><main class="login-main"><div class="login-form"><div class="eyebrow">ADMINISTRATOR ACCESS</div><h2>欢迎回来</h2><p>使用你的 Authelia 管理员账号登录。</p><a class="btn primary" href="${attr(authConfig.login_url)}">使用 Authelia 登录　→</a><p class="login-security">仅授权的管理员可进入。<br>登录和二次验证由 Authelia 完成。</p></div></main></div>`;
    return;
  }
  root.innerHTML = `<div class="login-layout"><aside class="login-aside"><div class="brand"><img src="${base}/assets/favicon.svg" alt=""><div><strong>Authelia Console</strong><small>IDENTITY, SIMPLIFIED</small></div></div><div class="login-statement"><div class="eyebrow">YOUR PRIVATE ACCESS DESK</div><h1>为每一个应用，<br>留一扇合适的门。</h1><p>在一个安静的工作台里，管理用户、应用和访问范围。让身份认证继续交给 Authelia。</p></div><div class="login-foot">SELF-HOSTED · BUILT FOR YOUR CIRCLE</div></aside><main class="login-main"><form id="login-form" class="login-form"><div class="eyebrow">ADMINISTRATOR ACCESS</div><h2>欢迎回来</h2><p>登录你的访问管理工作台。</p><div class="field"><label for="username">管理员账号</label><input id="username" name="username" autocomplete="username" value="admin" required></div><div class="field"><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required></div><div id="login-error" class="form-error" role="alert"></div><button class="btn primary" type="submit">登录工作台　→</button><p class="login-security">此处使用独立的后台管理员账号。<br>即使 Authelia 配置需要恢复，你仍可进入工作台。</p></form></main></div>`;
  document.querySelector("#login-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.currentTarget,
      b = f.querySelector("button");
    b.disabled = true;
    b.textContent = "正在验证…";
    try {
      const s = await api("login", "POST", Object.fromEntries(new FormData(f)));
      csrf = s.csrf;
      await refresh();
    } catch (err) {
      document.querySelector("#login-error").textContent = err.message;
    } finally {
      b.disabled = false;
      b.textContent = "登录工作台　→";
    }
  };
}
function matchingUsers(a) {
  if (a.access === "all") return state.users.filter((u) => !u.disabled);
  if (a.access !== "restricted") return [];
  return state.users.filter(
    (u) =>
      !u.disabled &&
      (a.subjects.includes("user:" + u.username) ||
        u.groups.some((g) => a.subjects.includes("group:" + g))),
  );
}
function badges(a) {
  if (a.access === "deny") return '<span class="pill red">已停用</span>';
  if (a.advanced) return '<span class="pill neutral">高级策略</span>';
  return '<span class="pill">已配置</span>';
}
function render() {
  if (!state) return;
  root.innerHTML = `<div class="layout"><aside class="sidebar"><div class="brand"><img src="${base}/assets/favicon.svg" alt=""><div><strong>Authelia Console</strong><small>ACCESS WORKSPACE</small></div></div><div class="workspace"><div class="small">当前实例</div><strong>${e(state.issuer.replace(/^https?:\/\//, "")) || "Authelia 实例"}</strong></div><div class="nav-label">WORKSPACE</div><nav class="nav" aria-label="主导航">${Object.keys(
    titles,
  )
    .map(
      (k) =>
        `<button data-nav="${k}" class="${page === k ? "active" : ""}"><span class="icon">${icons[k]}</span>${titles[k]}<span class="count">${k === "applications" ? state.applications.length : k === "users" ? state.users.length : k === "groups" ? state.groups.length : k === "rules" ? state.proxy_rules.length : state.history.length}</span></button>`,
    )
    .join(
      "",
    )}</nav><div class="sidebar-foot"><div class="small"><span class="status-dot"></span>${state.can_publish ? "发布代理已连接配置" : "本地编辑模式"}</div><div class="help muted">单实例 · 配置工作台</div><button id="logout" class="logout">退出工作台 ↗</button></div></aside><main class="main"><header class="topbar"><div class="breadcrumb"><span>工作台</span><span>/</span><b>${titles[page]}</b></div><div class="top-actions"><button id="changes" class="btn changes-btn">查看变更 <span class="pending">${state.changes.length}</span></button><span class="avatar" title="${attr(currentUsername)}">${e(currentUsername.slice(0,2).toUpperCase())}</span></div></header><div class="page-head"><div><div class="eyebrow">${page === "applications" ? "APPLICATION DIRECTORY" : page === "users" ? "PEOPLE & IDENTITIES" : page === "groups" ? "GROUP MEMBERSHIPS" : page === "rules" ? "FORWARDAUTH POLICIES" : "CONFIGURATION HISTORY"}</div><h1>${titles[page]}</h1><p class="subtitle">${subs[page]}</p></div>${page !== "history" ? `<button id="add" class="btn primary">＋ ${page === "applications" ? "添加应用" : page === "users" ? "添加用户" : page === "rules" ? "添加规则" : "创建用户组"}</button>` : ""}</div>${state.conflict ? '<div class="notice error">线上配置或用户密码已被外部修改。当前草稿已暂停发布，请在查看变更中保留差异，再丢弃草稿并重新导入。</div>' : ""}${!state.can_publish ? '<div class="notice warning">当前为隔离编辑环境，可以编辑草稿。尚未连接线上发布代理，发布按钮不可用。</div>' : ""}<section id="page-content">${page === "applications" ? applicationsPage() : page === "users" ? usersPage() : page === "groups" ? groupsPage() : page === "rules" ? rulesPage() : historyPage()}</section><footer class="page-foot"><span>AUTHELIA CONSOLE / v0.3.0</span><span>YOUR APPS. YOUR PEOPLE. YOUR CONTROL.</span></footer></main></div>`;
  root.querySelectorAll("[data-nav]").forEach(
    (b) =>
      (b.onclick = () => {
        page = b.dataset.nav;
        query = "";
        filter = "all";
        render();
      }),
  );
  document.querySelector("#logout").onclick = async () => {
    try {
      await api("logout", "POST", {});
      csrf = "";
      state = null;
      loginPage();
    } catch (err) {
      toast(err.message, true);
    }
  };
  document.querySelector("#changes").onclick = () => changesDialog();
  if (page !== "history")
    document.querySelector("#add").onclick = () =>
      page === "applications"
        ? appDialog()
        : page === "users"
          ? userDialog()
          : page === "rules"
            ? ruleDialog()
            : groupDialog();
  bindPage();
}
function stats() {
  return `<div class="stats"><div class="stat"><div><label>接入应用</label><strong>${String(state.applications.length).padStart(2, "0")}</strong></div><span class="stat-icon">◈</span></div><div class="stat"><div><label>活跃用户</label><strong>${String(state.users.filter((u) => !u.disabled).length).padStart(2, "0")}</strong></div><span class="stat-icon">♙</span></div><div class="stat"><div><label>用户组</label><strong>${String(state.groups.length).padStart(2, "0")}</strong></div><span class="stat-icon">⊞</span></div></div>`;
}
function toolbar(filters = "") {
  return `<div class="toolbar"><div class="filters">${filters}</div><input id="search" class="search" type="search" aria-label="搜索" placeholder="搜索名称或标识…" value="${attr(query)}"></div>`;
}
function applicationsPage() {
  return (
    stats() +
    toolbar(
      [
        ["all", "全部应用"],
        ["oidc", "OIDC 登录"],
        ["proxy", "代理保护"],
      ]
        .map(
          ([v, t]) =>
            `<button class="filter ${filter === v ? "active" : ""}" data-filter="${v}">${t}</button>`,
        )
        .join(""),
    ) +
    '<div id="listing" class="app-grid">' +
    appList() +
    "</div>" +
    `<div class="notice">这里展示的是登录授权配置。应用内部权限及已有会话由应用管理；停用登录不会自动注销应用已有会话。</div><div class="legacy rules-link"><div><h3>公开路径与代理访问</h3><p class="help">${state.proxy_rules.length} 条 ForwardAuth 规则，包含免登录路径、身份限制和兜底策略。</p></div><button class="btn" data-show-rules>管理代理规则 →</button></div>`
  );
}
function appList() {
  const apps = state.applications.filter(
    (a) =>
      (filter === "all" || a.kind === filter) &&
      [a.name, a.client_id, ...(a.domains || [])]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return apps.length
    ? apps
        .map(
          (a) =>
            `<article class="app-card ${a.kind}"><div class="card-top"><div class="app-symbol">${e(a.name.slice(0, 1).toUpperCase())}</div><div class="card-title"><h3>${e(a.name)}</h3><span class="mono">${e(a.client_id || (a.domains || []).join(", "))}</span></div>${badges(a)}</div><div class="card-body"><div class="detail-row"><span>接入方式</span><span>${a.kind === "oidc" ? "OpenID Connect" : "ForwardAuth 代理保护"}</span></div><div class="detail-row"><span>登录授权</span><span>${a.access === "all" ? "全部有效用户" : a.access === "deny" ? "拒绝所有登录" : a.advanced ? "保留高级策略" : `<span class="tags">${a.subjects.map((s) => `<span class="tag">${e(s.replace("user:", "♙ ").replace("group:", "⊞ "))}</span>`).join("")}</span>`}</span></div><div class="detail-row"><span>二次验证</span><span>${a.mfa ? "要求 MFA" : "仅密码验证"}</span></div></div><div class="card-footer"><span class="small">${a.advanced ? "自定义条件" : `${matchingUsers(a).length} 位有效用户符合登录策略`}</span><div><button class="btn ghost" data-connect="${attr(a.id)}">接入参数 ↗</button><button class="btn ghost" data-edit-app="${attr(a.id)}">${a.advanced ? "查看" : "管理 →"}</button></div></div></article>`,
        )
        .join("")
    : '<div class="empty"><h3>没有找到应用</h3><p>添加一个应用，开始管理它的登录和访问范围。</p></div>';
}
function usersPage() {
  return (
    toolbar() +
    '<div id="listing">' +
    userList() +
    "</div>" +
    '<div class="notice">停用用户会阻止后续登录。已签发的令牌及应用会话不会被即时撤销。</div>'
  );
}
function userList() {
  const us = state.users.filter((u) =>
    [u.username, u.displayname, u.email]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return `<div class="table-wrap"><table><thead><tr><th>用户</th><th>邮箱</th><th>用户组</th><th>状态</th><th></th></tr></thead><tbody>${us.map((u) => `<tr><td><div class="person"><span class="avatar">${e(u.displayname.slice(0, 1))}</span><div><strong>${e(u.displayname)}</strong><small>${e(u.username)}</small></div></div></td><td>${e(u.email) || '<span class="muted">—</span>'}</td><td>${u.groups.map((g) => `<span class="tag">${e(g)}</span>`).join(" ") || '<span class="muted">未分组</span>'}</td><td><span class="pill ${u.disabled ? "neutral" : ""}">${u.disabled ? "已停用" : "有效"}</span></td><td><div class="table-actions"><button class="btn ghost" data-edit-user="${attr(u.username)}">管理 →</button></div></td></tr>`).join("") || '<tr><td colspan="5" class="muted">没有匹配的用户</td></tr>'}</tbody></table></div>`;
}
function groupsPage() {
  return (
    toolbar() + '<div class="group-grid" id="listing">' + groupList() + "</div>"
  );
}
function groupList() {
  const gs = state.groups.filter((g) =>
    g.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    gs
      .map((g) => {
        const members = state.users.filter((u) => u.groups.includes(g));
        const apps = state.applications.filter((a) => a.subjects.includes("group:" + g));
        return `<article class="group-card"><header class="group-title"><span class="group-symbol" aria-hidden="true">⊞</span><div class="group-identity"><h3>${e(g)}</h3><p>${members.length} 位成员<span aria-hidden="true"> · </span>${apps.length} 个应用直接引用</p></div></header><div class="group-content"><section><h4 class="group-section-label">成员</h4><div class="group-members">${members.map((u) => `<span class="member-chip${u.disabled ? " disabled" : ""}" title="${attr(u.displayname)} (${attr(u.username)})"><span class="member-avatar" aria-hidden="true">${e(Array.from(u.displayname || u.username)[0].toUpperCase())}</span><span class="member-name">${e(u.displayname)}${u.displayname !== u.username ? `<small>${e(u.username)}</small>` : ""}</span>${u.disabled ? '<span class="member-status">已停用</span>' : ""}</span>`).join("") || '<p class="group-empty">还没有成员</p>'}</div></section><section><h4 class="group-section-label">应用引用</h4><div class="group-apps">${apps.map((a) => `<span class="group-app-tag" title="${attr(a.name)}">${e(a.name)}</span>`).join("") || '<p class="group-empty">暂无应用直接引用</p>'}</div></section></div><button class="btn ghost group-edit" data-edit-group="${attr(g)}" aria-label="编辑 ${attr(g)} 的成员">编辑成员 →</button></article>`;
      })
      .join("") ||
    '<div class="empty"><h3>还没有用户组</h3><p>可以直接给用户授权，也可以通过用户组批量管理。</p></div>'
  );
}
function historyPage() {
  return (
    `<div class="notice">保存最近 20 次成功发布前的快照。回滚会再次校验和发布；若用户密码或线上配置已变化，会阻止覆盖。</div>` +
    (state.history.length
      ? state.history
          .map(
            (h, i) =>
              `<article class="history-item"><div class="history-time">${e(new Date(h.at).toLocaleString("zh-CN"))}<br><span class="small">${e(h.id.slice(0, 12))}</span></div><ul>${h.summary.map((s) => `<li>${e(s)}</li>`).join("")}</ul><button class="btn sml" data-rollback="${attr(h.id)}" ${i > 0 ? 'disabled title="仅允许恢复最近一次发布前的快照，避免覆盖较新的配置"' : ""}>恢复发布前版本</button></article>`,
          )
          .join("")
      : '<div class="empty"><h3>尚无发布记录</h3><p>第一次成功应用配置后，会在这里保留恢复快照。</p></div>')
  );
}

const policyNames = {
  bypass: "免登录放行",
  deny: "拒绝访问",
  one_factor: "密码验证",
  two_factor: "二次验证 MFA",
};
const ruleFields = [
  "domain",
  "domain_regex",
  "resources",
  "methods",
  "networks",
  "subject",
  "policy",
];
const listOf = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const lines = (v) =>
  String(v || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
function policyOptions(value) {
  return Object.entries(policyNames)
    .map(
      ([v, t]) =>
        `<option value="${v}" ${v === value ? "selected" : ""}>${t}</option>`,
    )
    .join("");
}
function ruleHeading(r) {
  if (r.policy === "bypass")
    return r.resources ? "公开路径豁免" : "整个域名免登录";
  if (r.policy === "deny") return r.subject ? "身份访问限制" : "拒绝兜底";
  return r.subject ? "指定用户或组登录" : "应用登录要求";
}
function ruleSubjects(value) {
  return (
    listOf(value)
      .map((g) =>
        listOf(g)
          .map((s) => s.replace(/^user:/, "用户 ").replace(/^group:/, "组 "))
          .join(" 且 "),
      )
      .join(" 或 ") || "不限定身份"
  );
}
function rulesPage() {
  return `<div class="rule-intro"><div><div class="eyebrow">REQUEST → FIRST MATCH → POLICY</div><p>按顺序检查，<strong>第一条满足所有条件的规则生效</strong>。公开资源豁免通常排在对应的登录规则之前。</p><p class="help">这些规则只作用于已接入 ForwardAuth 的代理路由，独立于 OIDC 客户端的登录授权。</p></div><button class="btn" id="check-policy" ${!state.can_publish ? 'disabled title="需要连接发布代理"' : ""}>检查请求命中 ↗</button></div><form class="default-policy" id="proxy-default"><div><strong>未匹配任何规则时</strong><p class="help">保持现有默认策略，修改后需发布才生效。</p></div><select name="policy" aria-label="代理默认策略">${policyOptions(state.default_policy)}</select><button class="btn" type="submit">保存草稿</button></form>${toolbar(`<span class="help">${state.proxy_rules.length} 条规则 · ${state.proxy_rules.filter((x) => x.rule.policy === "bypass").length} 条免登录豁免</span>`)}<div class="rule-list" id="listing">${ruleList()}</div><div class="notice">编辑、排序和删除都先保存到草稿。额外条件（如查询参数）会原样保留；可在规则详情中查看，并通过原生检查确认匹配结果。</div>`;
}
function ruleList() {
  const visible = state.proxy_rules.filter((item) =>
    JSON.stringify(item.rule).toLowerCase().includes(query.toLowerCase()),
  );
  return (
    visible
      .map((item) => {
        const r = item.rule,
          extra = Object.keys(r).filter((k) => !ruleFields.includes(k));
        const domains = listOf(r.domain),
          regex = listOf(r.domain_regex);
        return `<article class="rule-card policy-${attr(r.policy)}"><div class="rule-number"><strong>${String(item.position).padStart(2, "0")}</strong><span>${item.managed ? "应用生成" : "手工规则"}</span></div><div class="rule-content"><div class="rule-title"><h3>${ruleHeading(r)}</h3><span class="policy-badge policy-${attr(r.policy)}">${e(policyNames[r.policy] || r.policy)}</span></div><div class="rule-domains">${domains.map((d) => `<code>${e(d)}</code>`).join(' <span class="muted small">或</span> ')}${domains.length && regex.length ? ' <span class="muted small">或</span> ' : ""}${regex.map((d) => `<span class="regex-label">正则</span> <code>${e(d)}</code>`).join(' <span class="muted small">或</span> ')}</div><div class="rule-criteria"><div><label>路径</label><span>${
          r.resources
            ? listOf(r.resources)
                .map((p) => `<code>${e(p)}</code>`)
                .join(' <span class="muted">或</span> ')
            : '<span class="muted">全部路径</span>'
        }</span></div><div><label>身份</label><span>${e(ruleSubjects(r.subject))}</span></div>${
          r.methods
            ? `<div><label>方法</label><span>${listOf(r.methods)
                .map((m) => `<span class="tag">${e(m)}</span>`)
                .join(" ")}</span></div>`
            : ""
        }${
          r.networks
            ? `<div><label>来源</label><span>${listOf(r.networks)
                .map((n) => `<code>${e(n)}</code>`)
                .join(" 或 ")}</span></div>`
            : ""
        }${extra.length ? `<div><label>额外条件</label><span class="muted">${e(extra.join(", "))} · 原样保留</span></div>` : ""}</div></div><div class="rule-actions">${item.managed ? '<button class="btn ghost" data-show-apps>在应用中管理 ↗</button>' : `<div class="rule-order"><button class="btn sml" data-move-rule="${item.index}" data-direction="-1" aria-label="上移规则 ${item.position}" ${item.index === 0 ? "disabled" : ""}>↑</button><button class="btn sml" data-move-rule="${item.index}" data-direction="1" aria-label="下移规则 ${item.position}" ${item.index === state.legacy_rules.length - 1 ? "disabled" : ""}>↓</button></div><button class="btn ghost" data-edit-rule="${item.index}">编辑规则 →</button>`}</div></article>`;
      })
      .join("") ||
    '<div class="empty"><h3>没有匹配的代理规则</h3><p>添加规则来定义公开路径、登录要求或拒绝策略。</p></div>'
  );
}
function textArea(label, name, value, help = "", placeholder = "") {
  return `<div class="field"><label for="rule-${name}">${e(label)}</label><textarea id="rule-${name}" name="${name}" placeholder="${attr(placeholder)}">${e(value)}</textarea>${help ? `<p class="help">${e(help)}</p>` : ""}</div>`;
}
function ruleDialog(item) {
  const old = !!item,
    r = item?.rule || { policy: "bypass" };
  const extra = Object.fromEntries(
    Object.entries(r).filter(([k]) => !ruleFields.includes(k)),
  );
  const subjectText = listOf(r.subject)
    .map((g) => listOf(g).join(" & "))
    .join("\n");
  openDialog(
    old ? `编辑代理规则 #${item.position}` : "添加代理规则",
    "保持规则顺序；每条规则的所有条件都需满足。",
    `<form id="rule-form"><div class="field"><label for="rule-policy">生效策略</label><select id="rule-policy" name="policy">${policyOptions(r.policy)}</select></div>${!old ? `<div class="field"><label for="rule-position">插入位置</label><select id="rule-position" name="insert_before">${state.legacy_rules.map((x, i) => `<option value="${i}">在规则 #${state.managed_rule_count + i + 1} 之前</option>`).join("")}<option value="${state.legacy_rules.length}">最后一条（默认策略之前）</option></select><p class="help">公开路径豁免应位于可能匹配它的身份限制和登录规则之前。</p></div>` : ""}${textArea("域名（每行一个）", "domain", listOf(r.domain).join("\n"), "支持完整域名或 *.example.com；域名与域名正则之间为“或”。", "note.example.com")}${textArea("域名正则（可选，每行一个）", "domain_regex", listOf(r.domain_regex).join("\n"), "使用 Authelia 的 Go / RE2 正则语法。", "^.*$")}${textArea("路径条件（正则，每行一个）", "resources", listOf(r.resources).join("\n"), "多个路径正则之间为“或”；留空表示全部路径。", "^/assets/.*$\n^/share/.*$")}<div class="rule-bypass-help notice ${r.policy === "bypass" ? "" : "hidden"}">匹配此规则的请求无需登录。它只豁免填写的域名、路径和方法，不影响后续未匹配请求的登录要求。</div>${textArea("身份条件（可选）", "subject", subjectText, "每行之间为“或”；同一行用 & 表示“且”。免登录规则不使用身份条件。", "user:alice\ngroup:admins & group:friends")}<div class="form-row"><div class="field"><label for="rule-methods">HTTP 方法（可选）</label><input id="rule-methods" name="methods" value="${attr(listOf(r.methods).join(", "))}" placeholder="例如 GET, HEAD"><p class="help">留空匹配全部方法，填写大写方法名。</p></div><div class="field"><label for="rule-networks">来源 IP / 网络（可选，每行一个）</label><textarea id="rule-networks" name="networks" placeholder="192.168.1.0/24">${e(listOf(r.networks).join("\n"))}</textarea><p class="help">可使用 IP、CIDR 或已有命名网络。</p></div></div>${Object.keys(extra).length ? `<details><summary class="help">额外条件将原样保留</summary><pre>${e(JSON.stringify(extra, null, 2))}</pre></details>` : ""}<div class="form-error" role="alert"></div></form>`,
    `${old ? '<button class="btn danger left" id="delete-rule">删除规则</button>' : ""}<button class="btn" data-close>取消</button><button class="btn primary" form="rule-form" type="submit">保存草稿</button>`,
  );
  const form = document.querySelector("#rule-form"),
    policy = form.querySelector("[name=policy]");
  function policyChange() {
    const bypass = policy.value === "bypass";
    form.querySelector("[name=subject]").disabled = bypass;
    form.querySelector(".rule-bypass-help").classList.toggle("hidden", !bypass);
  }
  policy.onchange = policyChange;
  policyChange();
  bindSave("rule-form", "proxy-rules", (f) => ({
    index: old ? item.index : null,
    insert_before: Number(f.get("insert_before") || 0),
    policy: f.get("policy"),
    domain: lines(f.get("domain")),
    domain_regex: lines(f.get("domain_regex")),
    resources: lines(f.get("resources")),
    methods: String(f.get("methods") || "")
      .split(/[\s,]+/)
      .filter(Boolean),
    networks: lines(f.get("networks")),
    subject: lines(f.get("subject")).map((line) =>
      line.split("&").map((x) => x.trim()),
    ),
  }));
  if (old)
    document.querySelector("#delete-rule").onclick = () =>
      performConfirm(
        `删除代理规则 #${item.position}？`,
        "后续请求将继续匹配后面的规则或默认策略。删除免登录豁免可能导致公开资源需要登录。",
        async () => {
          await api("proxy-rules/" + item.index, "DELETE", {
            version: state.version,
          });
          await refresh();
          toast("规则删除已保存到草稿");
        },
      );
}
function checkPolicyDialog() {
  openDialog(
    "检查代理请求",
    "使用当前草稿和 Authelia 原生引擎检查，不发起目标网站请求，也不发布配置。",
    `<form id="policy-check-form">${field("请求 URL", "url", "", "url", 'required placeholder="https://note.example.com/assets/app.css"')}<div class="form-row"><div class="field"><label for="check-method">HTTP 方法</label><input id="check-method" name="method" value="GET" required maxlength="32"></div><div class="field"><label for="check-ip">来源 IP（可选）</label><input id="check-ip" name="ip" placeholder="例如 192.168.1.10"></div></div><div class="field"><label for="check-user">用户身份</label><select id="check-user" name="username"><option value="">未登录 / 匿名请求</option>${state.users.map((u) => `<option value="${attr(u.username)}">${e(u.displayname)} (${e(u.username)})${u.disabled ? " · 已停用" : ""}</option>`).join("")}</select><p class="help">用户组自动取自当前草稿。匿名请求遇到身份条件时，可能需要先登录才能确定结果。</p></div><div class="form-error" role="alert"></div></form><div id="policy-result" aria-live="polite"></div>`,
    `<button class="btn" data-close>关闭</button><button class="btn primary" type="submit" form="policy-check-form">检查命中</button>`,
  );
  const form = document.querySelector("#policy-check-form");
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const b = mc.querySelector("[type=submit]");
    b.disabled = true;
    busy = true;
    const error = form.querySelector(".form-error");
    error.textContent = "";
    document.querySelector("#policy-result").innerHTML =
      '<p class="help">Authelia 正在检查草稿…</p>';
    try {
      const params = Object.fromEntries(new FormData(form)),
        result = await api("check-policy", "POST", {
          ...params,
          version: state.version,
        });
      renderPolicyResult(result);
    } catch (err) {
      error.textContent = err.message;
      document.querySelector("#policy-result").innerHTML = "";
    } finally {
      b.disabled = false;
      busy = false;
    }
  };
}
function renderPolicyResult(result) {
  const labels = { hit: "命中", miss: "不匹配", may: "需身份确认" };
  const summary = result.potential
    ? "需要先登录以确定身份条件"
    : result.policy
      ? policyNames[result.policy]
      : "请查看原生检查输出";
  document.querySelector("#policy-result").innerHTML =
    `<div class="policy-result"><div class="rule-title"><h3>${e(summary)}</h3>${result.position ? `<span class="policy-badge policy-${attr(result.policy)}">规则 #${result.position}</span>` : result.policy ? '<span class="pill neutral">默认策略</span>' : ""}</div>${result.disabled_user ? '<div class="notice warning">此用户在草稿中已停用。下方仅分析规则匹配，不表示该账号能够登录。</div>' : ""}<div class="table-wrap"><table class="match-table"><thead><tr><th>规则</th>${["域名", "路径", "查询参数", "方法", "来源", "身份"].map((t) => `<th>${t}</th>`).join("")}</tr></thead><tbody>${result.rows.map((row) => `<tr class="${row.marker === "*" ? "native-match" : row.marker === "~" ? "native-potential" : ""}"><td>${row.marker === "*" ? "● " : row.marker === "~" ? "◌ " : ""}#${row.position}</td>${row.criteria.map((c) => `<td><span class="match-${c}">${labels[c] || e(c)}</span></td>`).join("")}</tr>`).join("")}</tbody></table></div><p class="help">● 首个完全命中的规则　◌ 匿名请求的潜在身份匹配</p><details><summary class="help">查看 Authelia 原始检查输出</summary><pre>${e(result.report)}</pre></details></div>`;
}
function bindPage() {
  root.querySelectorAll("[data-filter]").forEach(
    (b) =>
      (b.onclick = () => {
        filter = b.dataset.filter;
        render();
      }),
  );
  const search = document.querySelector("#search");
  if (search)
    search.oninput = () => {
      query = search.value;
      document.querySelector("#listing").innerHTML =
        page === "applications"
          ? appList()
          : page === "users"
            ? userList()
            : page === "rules"
              ? ruleList()
              : groupList();
      bindItems();
    };
  bindItems();
  const check = document.querySelector("#check-policy");
  if (check) check.onclick = checkPolicyDialog;
  const defaults = document.querySelector("#proxy-default");
  if (defaults)
    defaults.onsubmit = async (ev) => {
      ev.preventDefault();
      const button = defaults.querySelector("button");
      button.disabled = true;
      try {
        await api("proxy-default", "POST", {
          version: state.version,
          policy: new FormData(defaults).get("policy"),
        });
        await refresh();
        toast("默认策略已保存到草稿");
      } catch (err) {
        toast(err.message, true);
      } finally {
        button.disabled = false;
      }
    };
}
function bindItems() {
  root.querySelectorAll("[data-show-rules]").forEach(
    (b) =>
      (b.onclick = () => {
        page = "rules";
        query = "";
        render();
      }),
  );
  root.querySelectorAll("[data-show-apps]").forEach(
    (b) =>
      (b.onclick = () => {
        page = "applications";
        query = "";
        render();
      }),
  );
  root
    .querySelectorAll("[data-edit-rule]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          ruleDialog(
            state.proxy_rules.find(
              (r) => r.index === Number(b.dataset.editRule),
            ),
          )),
    );
  root.querySelectorAll("[data-move-rule]").forEach(
    (b) =>
      (b.onclick = async () => {
        b.disabled = true;
        try {
          await api("proxy-rules/move", "POST", {
            version: state.version,
            index: Number(b.dataset.moveRule),
            direction: Number(b.dataset.direction),
          });
          await refresh();
          toast("规则顺序已保存到草稿");
        } catch (err) {
          toast(err.message, true);
          b.disabled = false;
        }
      }),
  );
  root
    .querySelectorAll("[data-edit-app]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          appDialog(
            state.applications.find((a) => a.id === b.dataset.editApp),
          )),
    );
  root
    .querySelectorAll("[data-connect]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          connectDialog(
            state.applications.find((a) => a.id === b.dataset.connect),
          )),
    );
  root
    .querySelectorAll("[data-edit-user]")
    .forEach(
      (b) =>
        (b.onclick = () =>
          userDialog(
            state.users.find((u) => u.username === b.dataset.editUser),
          )),
    );
  root
    .querySelectorAll("[data-edit-group]")
    .forEach((b) => (b.onclick = () => groupDialog(b.dataset.editGroup)));
  root.querySelectorAll("[data-rollback]").forEach(
    (b) =>
      (b.onclick = () =>
        performConfirm(
          "恢复发布前版本？",
          "Authelia 将重新启动。当前文件必须仍与该次发布结果一致。",
          async () => {
            await api(
              "rollback/" + encodeURIComponent(b.dataset.rollback),
              "POST",
              { version: state.version },
            );
            await refresh();
            toast("已恢复发布前版本，健康检查通过");
          },
        )),
  );
}
function openDialog(title, subtitle, body, footer = "") {
  mc.innerHTML = `<div class="modal-head"><div><h2>${e(title)}</h2><p>${e(subtitle)}</p></div><button class="close" aria-label="关闭">×</button></div><div class="modal-body">${body}</div>${footer ? `<div class="modal-foot">${footer}</div>` : ""}`;
  mc.querySelector(".close").onclick = () => {
    if (!busy) modal.close();
  };
  mc.querySelectorAll("[data-close]").forEach(
    (b) => (b.onclick = () => modal.close()),
  );
  if (!modal.open) modal.showModal();
}
modal.addEventListener("cancel", (ev) => {
  if (busy) ev.preventDefault();
});
function field(label, name, value = "", type = "text", extra = "") {
  return `<div class="field"><label for="f-${name}">${label}</label><input id="f-${name}" name="${name}" type="${type}" value="${attr(value)}" ${extra}></div>`;
}
function checks(name, items, selected) {
  return `<div class="checks">${items.map(([v, t]) => `<label class="check"><input type="checkbox" name="${name}" value="${attr(v)}" ${selected.includes(v) ? "checked" : ""}>${e(t)}</label>`).join("")}</div>`;
}
function bindSave(formId, path, transform) {
  const f = document.querySelector("#" + formId);
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const btn = mc.querySelector("[type=submit]");
    btn.disabled = true;
    try {
      await api(path, "POST", {
        ...transform(new FormData(f)),
        version: state.version,
      });
      modal.close();
      await refresh();
      toast("已保存到草稿，尚未修改线上配置");
    } catch (err) {
      f.querySelector(".form-error").textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  };
}
function userDialog(u) {
  const old = !!u;
  u = u || {
    username: "",
    displayname: "",
    email: "",
    groups: [],
    disabled: false,
  };
  const allowed = state.applications.filter((a) =>
    matchingUsers(a).some((x) => x.username === u.username),
  );
  openDialog(
    old ? "管理用户" : "添加用户",
    "修改将先保存到草稿，发布后生效。",
    `<form id="user-form"><div class="form-row">${field("用户名", "username", u.username, "text", old ? "readonly" : 'required maxlength="80" autocomplete="off"')}${field("显示名称", "displayname", u.displayname, "text", 'required maxlength="100"')}</div>${field("邮箱", "email", u.email, "email")}${field(old ? "新密码（留空保留原密码）" : "初始密码（至少 12 字符）", "password", "", "password", `${old ? "" : "required"} minlength="12" autocomplete="new-password"`)}<div class="field"><label>用户组</label>${
      state.groups.length
        ? checks(
            "groups",
            state.groups.map((g) => [g, g]),
            u.groups,
          )
        : '<p class="help">尚无用户组，可以之后再分配。</p>'
    }</div><div class="toggle-line"><label><input type="checkbox" name="disabled" ${u.disabled ? "checked" : ""}>停用此用户</label></div>${old ? `<div class="field"><label>符合登录策略的应用</label><div class="tags">${allowed.map((a) => `<span class="tag">${e(a.name)}</span>`).join("") || '<span class="help">暂无</span>'}</div><p class="help">仅依据本后台可解析的策略计算，不包含历史代理规则及应用内部权限。</p></div>` : ""}<div class="form-error" role="alert"></div></form>`,
    `${old ? '<button id="delete-user" class="btn danger left">删除用户</button>' : ""}<button class="btn" data-close>取消</button><button class="btn primary" form="user-form" type="submit">保存草稿</button>`,
  );
  bindSave("user-form", "users", (f) => ({
    username: f.get("username"),
    displayname: f.get("displayname"),
    email: f.get("email"),
    password: f.get("password"),
    groups: f.getAll("groups"),
    disabled: f.has("disabled"),
    creating: !old,
  }));
  if (old)
    document.querySelector("#delete-user").onclick = () =>
      performConfirm(
        "删除用户 " + u.username + "？",
        "如果仍有策略直接引用该用户，系统将阻止删除。",
        async () => {
          await api("users/" + encodeURIComponent(u.username), "DELETE", {
            version: state.version,
          });
          await refresh();
          toast("删除操作已保存到草稿");
        },
      );
}
function groupDialog(name) {
  const old = !!name;
  const selected = state.users
    .filter((u) => u.groups.includes(name))
    .map((u) => u.username);
  openDialog(
    old ? "管理用户组" : "创建用户组",
    "成员变化会影响所有引用该组的应用。",
    `<form id="group-form">${field("组名称", "name", name || "", "text", old ? "readonly" : 'required maxlength="80"')}<div class="field"><label>组成员</label><div class="check-list">${state.users.map((u) => `<label class="check"><input type="checkbox" name="members" value="${attr(u.username)}" ${selected.includes(u.username) ? "checked" : ""}>${e(u.displayname)} <span class="muted mono">${e(u.username)}</span></label>`).join("") || '<p class="help">请先添加用户</p>'}</div></div><div class="form-error" role="alert"></div></form>`,
    `${old ? '<button id="delete-group" class="btn danger left">删除用户组</button>' : ""}<button class="btn" data-close>取消</button><button class="btn primary" form="group-form" type="submit">保存草稿</button>`,
  );
  bindSave("group-form", "groups", (f) => ({
    name: f.get("name"),
    members: f.getAll("members"),
  }));
  if (old)
    document.querySelector("#delete-group").onclick = () =>
      performConfirm(
        "删除用户组 " + name + "？",
        "仍被访问策略引用的用户组不能删除。",
        async () => {
          await api("groups/" + encodeURIComponent(name), "DELETE", {
            version: state.version,
          });
          await refresh();
          toast("用户组删除已保存到草稿");
        },
      );
}
function appDialog(a) {
  const old = !!a;
  a = {
    kind: "oidc",
    name: "",
    id: "",
    client_id: "",
    public: false,
    redirect_uris: [],
    domains: [],
    access: "restricted",
    subjects: [],
    mfa: true,
    scopes: ["openid", "profile", "email", "groups"],
    bypass_resources: [],
    bypass_methods: [],
    id_token_profile: false,
    ...a,
  };
  if (a.advanced) {
    openDialog(
      a.name,
      "该应用使用高级自定义策略，原样保留。",
      `<div class="notice">第一版暂不将复杂策略转换为简单勾选，以避免改变原有授权语义。</div><pre>${e(JSON.stringify(a, null, 2))}</pre>`,
      '<button class="btn" data-close>关闭</button>',
    );
    return;
  }
  openDialog(
    old ? "管理应用" : "添加应用",
    "统一配置接入方式、登录范围和二次验证。",
    `<form id="app-form">${old ? "" : `<div class="choice-grid"><label class="choice"><input type="radio" name="kind" value="oidc" checked><strong>OIDC 统一登录</strong><p>应用原生支持 OAuth2 / OpenID Connect</p></label><label class="choice"><input type="radio" name="kind" value="proxy"><strong>代理保护</strong><p>在 Traefik 前增加 Authelia 登录门禁</p></label></div>`}${field("应用名称", "name", a.name, "text", 'required maxlength="100"')}<div id="oidc-fields" class="${a.kind === "proxy" ? "hidden" : ""}">${field("Client ID", "client_id", a.client_id, "text", old ? "readonly" : 'maxlength="200" placeholder="例如 photos"')}<div class="field"><label for="f-redirects">回调地址（每行一个）</label><textarea name="redirect_uris" id="f-redirects" placeholder="https://photos.example.com/auth/callback">${e(a.redirect_uris.join("\n"))}</textarea><p class="help">支持 HTTPS、localhost 回调以及移动端自定义 URI。</p></div>${!old ? '<div class="toggle-line"><label><input type="checkbox" name="public">公开客户端（浏览器 SPA / 移动应用，无 Secret）</label></div><div class="field" id="secret-field"><label for="f-secret">Client Secret</label><div class="secret-row"><input id="f-secret" name="client_secret" autocomplete="off" spellcheck="false" placeholder="点击生成，并复制到应用端"><button class="btn" type="button" id="generate-secret">生成</button></div><p class="help">Secret 仅在创建时显示，保存后只保留哈希。请先复制。</p></div>' : `<p class="help">客户端类型：${a.public ? "公开客户端" : "机密客户端，保留现有 Secret 和认证方式"}</p>`}${!old ? '<div class="toggle-line"><label><input type="checkbox" name="require_pkce" checked>要求 PKCE（推荐）</label><span class="help">部分旧服务需关闭</span></div>' : ""}<div class="field"><label>Scopes</label>${checks(
      "scopes",
      ["openid", "profile", "email", "groups", "offline_access"].map((s) => [
        s,
        s,
      ]),
      a.scopes,
    )}</div><div class="toggle-line"><label><input type="checkbox" name="id_token_profile" ${a.id_token_profile ? "checked" : ""} ${a.id_token_profile === null ? "disabled" : ""}>在 ID Token 中包含姓名、邮箱和用户名</label><span class="help">适配 Trilium 等直接读取 ID Token 的应用；需要 profile 和 email Scope。</span></div>${a.id_token_profile === null ? '<p class="help">现有自定义 Claims 策略会原样保留。</p>' : ""}</div><div id="proxy-fields" class="${a.kind !== "proxy" ? "hidden" : ""}"><div class="field"><label for="f-domains">应用域名（每行一个）</label><textarea name="domains" id="f-domains" placeholder="photos.example.com">${e((a.domains || []).join("\n"))}</textarea><p class="help">保存后还需将该域名的 Traefik 路由接到 ForwardAuth 中间件。新增规则优先于手工规则。</p></div><div class="field"><label for="f-bypass">公开路径豁免（正则，每行一个）</label><textarea id="f-bypass" name="bypass_resources" placeholder="^/assets/.*$&#10;^/share/.*$">${e(a.bypass_resources.join("\n"))}</textarea><p class="help">匹配的路径无需登录，其余路径仍使用下面的授权和 MFA 设置。停用应用时这些豁免也会取消。</p></div><div class="field"><label for="f-bypass-methods">豁免的 HTTP 方法</label><input id="f-bypass-methods" name="bypass_methods" value="${attr(a.bypass_methods.join(", "))}" placeholder="留空为全部方法；例如 GET, HEAD"><p class="help">若设置 GET、HEAD，其他方法不会通过这条公开路径规则放行。</p></div></div><hr class="divider"><div class="field"><label for="access">允许谁登录</label><select id="access" name="access"><option value="restricted" ${a.access === "restricted" ? "selected" : ""}>指定用户或用户组</option><option value="all" ${a.access === "all" ? "selected" : ""}>全部有效用户</option><option value="deny" ${a.access === "deny" ? "selected" : ""}>拒绝所有登录（停用）</option></select><div id="subjects" class="check-list ${a.access !== "restricted" ? "hidden" : ""}"><div class="group-heading">用户组</div>${state.groups.map((g) => `<label class="check"><input type="checkbox" name="subjects" value="group:${attr(g)}" ${a.subjects.includes("group:" + g) ? "checked" : ""}>⊞ ${e(g)}</label>`).join("") || '<p class="help">尚无用户组</p>'}<div class="group-heading">用户</div>${state.users.map((u) => `<label class="check"><input type="checkbox" name="subjects" value="user:${attr(u.username)}" ${a.subjects.includes("user:" + u.username) ? "checked" : ""}>${e(u.displayname)} <span class="mono muted">${e(u.username)}${u.disabled ? " · 已停用" : ""}</span></label>`).join("")}</div></div><div class="toggle-line"><label><input type="checkbox" name="mfa" ${a.mfa ? "checked" : ""}>要求二次验证（MFA）</label><span class="help">默认开启</span></div><div class="form-error" role="alert"></div></form>`,
    `${old ? `<button id="delete-app" class="btn danger left">${a.kind === "proxy" ? "停用应用" : "删除应用"}</button>` : ""}<button class="btn" data-close>取消</button><button class="btn primary" form="app-form" type="submit">保存草稿</button>`,
  );
  const f = document.querySelector("#app-form");
  f.querySelectorAll("[name=kind]").forEach(
    (r) =>
      (r.onchange = () => {
        const k = f.querySelector("[name=kind]:checked").value;
        document
          .querySelector("#oidc-fields")
          .classList.toggle("hidden", k !== "oidc");
        document
          .querySelector("#proxy-fields")
          .classList.toggle("hidden", k !== "proxy");
      }),
  );
  document.querySelector("#access").onchange = (ev) =>
    document
      .querySelector("#subjects")
      .classList.toggle("hidden", ev.target.value !== "restricted");
  const pub = f.querySelector("[name=public]");
  if (pub)
    pub.onchange = () =>
      document
        .querySelector("#secret-field")
        .classList.toggle("hidden", pub.checked);
  const gen = document.querySelector("#generate-secret");
  if (gen)
    gen.onclick = async () => {
      try {
        f.querySelector("[name=client_secret]").value = (
          await api("secret", "POST", {})
        ).secret;
      } catch (err) {
        toast(err.message, true);
      }
    };
  bindSave("app-form", "applications", (v) => ({
    id: a.id,
    kind: old ? a.kind : v.get("kind"),
    creating: !old,
    name: v.get("name"),
    client_id: v.get("client_id"),
    redirect_uris: String(v.get("redirect_uris"))
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    domains: String(v.get("domains"))
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    public: old ? a.public : v.has("public"),
    client_secret: v.get("client_secret") || "",
    require_pkce: v.has("require_pkce"),
    id_token_profile: a.id_token_profile === null ? null : v.has("id_token_profile"),
    access: v.get("access"),
    subjects: v.getAll("subjects"),
    mfa: v.has("mfa"),
    scopes: v.getAll("scopes"),
    bypass_resources: lines(v.get("bypass_resources")),
    bypass_methods: String(v.get("bypass_methods") || "")
      .split(/[\s,]+/)
      .filter(Boolean),
  }));
  if (old)
    document.querySelector("#delete-app").onclick = () =>
      performConfirm(
        (a.kind === "proxy" ? "停用" : "删除") + "应用 " + a.name + "？",
        a.kind === "proxy"
          ? "保留域名拒绝规则，避免落入宽松默认策略。"
          : "应用将无法通过该 Client 发起新的 OIDC 登录。已有应用会话不受影响。",
        async () => {
          await api("applications/" + encodeURIComponent(a.id), "DELETE", {
            version: state.version,
          });
          await refresh();
          toast("变更已保存到草稿");
        },
      );
}
function connectDialog(a) {
  const issuer = state.issuer;
  const rows =
    a.kind === "oidc"
      ? [
          ["Issuer URL", issuer],
          ["Discovery URL", issuer + "/.well-known/openid-configuration"],
          ["Client ID", a.client_id],
          [
            "Client Secret",
            a.public
              ? "公开客户端，不需要 Secret"
              : "使用应用端原有 Secret；后台仅保留哈希，无法读取明文",
          ],
          ["Scopes", (a.scopes || []).join(" ")],
          ["PKCE", a.require_pkce ? "必需（S256）" : "可选"],
          ["ID Token 用户资料", a.id_token_profile === null ? "现有自定义策略" : a.id_token_profile ? "已包含姓名、邮箱、用户名" : "通过 UserInfo 提供"],
          ["回调地址", a.redirect_uris.join("\n")],
        ]
      : [
          ["应用域名", a.domains.join("\n")],
          ["ForwardAuth 地址", issuer + "/api/authz/forward-auth"],
        ];
  openDialog(
    a.name + " · 接入参数",
    a.kind === "oidc"
      ? "将这些参数填写到应用的 OIDC 登录设置中。"
      : "将中间件附加到应用的 Traefik 路由后，才能保护流量。",
    rows
      .map(
        ([k, v]) =>
          `<div class="instruction-row"><label>${e(k)}</label><code>${e(v)}</code></div>`,
      )
      .join("") +
      (a.kind === "proxy"
        ? `<pre>${e(`http:\n  middlewares:\n    authelia-auth:\n      forwardAuth:\n        address: ${issuer}/api/authz/forward-auth\n        trustForwardHeader: true\n        authResponseHeaders:\n          - Remote-User\n          - Remote-Groups\n          - Remote-Email\n          - Remote-Name\n\n# 路由中添加：\n# middlewares:\n#   - authelia-auth@file`)}</pre><p class="help">应用域名还需位于 Authelia 已配置的 session cookie 域范围内。API、Webhook 和移动客户端请单独检查兼容性。</p>`
        : "") +
      '<div class="notice">应用授权配置发布后生效；此处不会自动修改应用端设置。</div>',
    '<button class="btn primary" data-close>完成</button>',
  );
}
async function changesDialog() {
  try {
    const p = await api("preview");
    openDialog(
      "变更与发布",
      `${state.changes.length} 项草稿变更 · 保存草稿不会修改线上文件`,
      `${state.changes.length ? `<ol class="preview-list">${state.changes.map((s) => `<li>${e(s)}</li>`).join("")}</ol>` : '<p class="muted">目前没有待发布变更。</p>'}${state.conflict ? '<div class="notice error">线上文件已变化，不能覆盖发布。请保留下方差异并重新导入。</div>' : ""}<pre>${e(p.diff)}</pre><p class="help">密码、Client Secret 和签名密钥已隐藏。配置发布将短暂重启 Authelia，应用自身继续运行。</p><div id="publish-result" class="help" role="status"></div>`,
      `<button id="discard" class="btn danger left" ${!state.changes.length ? "disabled" : ""}>丢弃草稿</button><button id="validate" class="btn" ${!state.can_publish || state.conflict ? "disabled" : ""}>校验配置</button><button id="publish" class="btn primary" ${!state.changes.length || !state.can_publish || state.conflict ? "disabled" : ""}>应用 ${state.changes.length} 项变更</button>`,
    );
    document.querySelector("#discard").onclick = () =>
      performConfirm(
        "丢弃全部草稿？",
        "不会修改线上配置。下次打开会重新读取当前线上文件。",
        async () => {
          await api("discard", "POST", { version: state.version });
          await refresh();
          toast("已丢弃草稿并重新读取线上配置");
        },
      );
    document.querySelector("#validate").onclick = () => publishAction(true);
    document.querySelector("#publish").onclick = () =>
      performConfirm(
        "应用配置并重启 Authelia？",
        "系统会先校验、保存快照，再写入配置并重启。失败时自动恢复。",
        async () => {
          await api("publish", "POST", { version: state.version });
          await refresh();
          toast("配置已发布，Authelia 健康检查通过");
        },
      );
  } catch (err) {
    toast(err.message, true);
  }
}
async function publishAction() {
  busy = true;
  const buttons = [...mc.querySelectorAll("button")].map((b) => [
    b,
    b.disabled,
  ]);
  buttons.forEach(([b]) => (b.disabled = true));
  const r = document.querySelector("#publish-result");
  r.textContent = "正在使用 Authelia 校验配置…";
  try {
    const d = await api("validate", "POST", { version: state.version });
    r.textContent = d.message + (d.warnings ? " · " + d.warnings : "");
    toast(d.message);
  } catch (err) {
    r.textContent = err.message;
    toast(err.message, true);
  } finally {
    busy = false;
    buttons.forEach(([b, disabled]) => (b.disabled = disabled));
  }
}
function performConfirm(title, text, action) {
  openDialog(
    title,
    "请确认这次操作。",
    `<p>${e(text)}</p><div class="form-error" id="confirm-error" role="alert"></div>`,
    '<button class="btn" data-close>取消</button><button id="confirm-action" class="btn primary">确认</button>',
  );
  document.querySelector("#confirm-action").onclick = async () => {
    busy = true;
    mc.querySelectorAll("button").forEach((b) => (b.disabled = true));
    document.querySelector("#confirm-action").textContent = "处理中…";
    try {
      await action();
      modal.close();
    } catch (err) {
      document.querySelector("#confirm-error").textContent = err.message;
      toast(err.message, true);
    } finally {
      busy = false;
      mc.querySelectorAll("button").forEach((b) => (b.disabled = false));
      const b = document.querySelector("#confirm-action");
      if (b) b.textContent = "确认";
    }
  };
}
async function boot() {
  try {
    authConfig = await api("auth-config");
    const s = await api("session");
    csrf = s.csrf;
    currentUsername = s.username;
    await refresh();
  } catch {
    loginPage();
  }
}
boot();
