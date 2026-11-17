"use strict";

const state = {
  token: sessionStorage.getItem("scopepack.adminToken") || "",
  purposes: [],
  catalog: [],
  selected: null,
  detail: null,
  editing: new Set(),
  preview: null,
  pollTimer: null,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "html") node.innerHTML = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
};

function fmtBytes(n) {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}

function fmtTime(value) {
  if (!value) return "—";
  return value.replace("T", " ").replace("Z", " UTC");
}

function shortHash(value) {
  if (!value) return "—";
  return value.slice(0, 10) + "…" + value.slice(-4);
}

function toast(message, isError = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("err", isError);
  box.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { box.hidden = true; }, 4200);
}

function askToken() {
  const value = window.prompt("输入管理员令牌（X-Admin-Token）", state.token || "");
  if (value === null) return false;
  state.token = value.trim();
  sessionStorage.setItem("scopepack.adminToken", state.token);
  return true;
}

async function api(path, options = {}) {
  const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
  if (state.token) headers["X-Admin-Token"] = state.token;
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, Object.assign({}, options, { headers }));
  let payload = null;
  try { payload = await response.json(); } catch (_) { /* empty */ }
  if (response.status === 401) {
    if (askToken()) return api(path, options);
    throw new Error("需要管理员令牌");
  }
  if (!response.ok) {
    const message = payload?.error?.message || `HTTP ${response.status}`;
    const details = payload?.error?.details ? ` ${JSON.stringify(payload.error.details)}` : "";
    throw new Error(message + details);
  }
  return payload;
}

async function loadOverview() {
  const data = await api("/api/v1/admin/overview");
  state.purposes = data.purposes;
  state.catalog = data.field_catalog;
  $("#dataset-pill").textContent = `${data.dataset.version} · ${data.dataset.row_count} rows`;
  $("#health-pill").textContent = "registry 正常";
  $("#health-pill").className = "pill good";
  renderPurposes();
  renderNodes(data.nodes);
  if (state.selected) {
    const exists = state.purposes.find((p) => p.code === state.selected);
    if (exists) await loadPurpose(state.selected, true);
  }
  return data;
}

function renderPurposes() {
  const list = $("#purpose-list");
  list.replaceChildren();
  for (const purpose of state.purposes) {
    const button = el("button", {
      class: "purpose-item" + (purpose.code === state.selected ? " active" : ""),
      type: "button",
      onclick: () => selectPurpose(purpose.code),
    },
      el("span", { class: "name" }, purpose.name),
      el("span", { class: "meta" }, `${purpose.code} · policy v${purpose.policy.version} · ${purpose.allowed_fields.length} fields`),
    );
    list.append(button);
  }
}

function renderNodes(nodes) {
  const list = $("#node-list");
  list.replaceChildren();
  for (const node of nodes) {
    const meta = node.healthy
      ? `${fmtBytes(node.cache_bytes || 0)} · ${node.cached_packages || 0} pkg · ${node.active_sessions || 0} stream`
      : (node.detail || "unreachable");
    list.append(el("div", { class: "node " + (node.healthy ? "up" : "down") },
      el("div", {}, el("span", { class: "dot" }), el("strong", {}, node.node_id)),
      el("div", { class: "meta" }, meta),
    ));
  }
}

async function selectPurpose(code) {
  state.selected = code;
  state.editing = new Set();  // force editor state to re-initialize
  renderPurposes();
  await loadPurpose(code);
}

async function loadPurpose(code, quiet = false) {
  try {
    const data = await api(`/api/v1/admin/purposes/${encodeURIComponent(code)}`);
    const changedPurpose = state.detail?.purpose?.code !== data.purpose.code;
    state.detail = data;
    renderPurpose(data);
    if (changedPurpose || !state.editing.size) {
      state.editing = new Set(data.allowed_fields);
    }
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

function renderPurpose(data) {
  $("#empty").hidden = true;
  $("#purpose-view").hidden = false;
  $("#purpose-view").dataset.purpose = data.purpose.code;
  $("#purpose-code").textContent = data.purpose.code;
  $("#purpose-name").textContent = data.purpose.name;
  $("#purpose-desc").textContent = data.purpose.description;
  $("#policy-badge").replaceChildren(
    el("span", { class: "muted small" }, "当前策略"),
    el("strong", {}, `v${data.policy.version}`),
    el("span", { class: "muted" }, `hash ${shortHash(data.policy.policy_hash)}`),
  );
  renderFields(data);
  renderPackages(data.packages);
  renderContracts(data.contracts);
  renderActivity(data);
}

function renderFields(data) {
  const grid = $("#field-grid");
  grid.replaceChildren();
  const rules = new Map(data.rules.map((r) => [r.field, r]));
  const allowed = new Set(data.allowed_fields);
  for (const field of data.field_catalog) {
    const rule = rules.get(field.field);
    const isAllowed = allowed.has(field.field);
    grid.append(el("div", { class: "field-card " + (isAllowed ? "allowed" : "denied") },
      el("div", {}, el("span", { class: "fname" }, field.field), " ",
        el("span", { class: "sens " + field.sensitivity }, field.sensitivity)),
      el("div", { class: "fmeta" }, `${field.category} · ${field.description}`),
      !isAllowed && rule ? el("div", { class: "freason" }, rule.reason) : null,
    ));
  }
}

function statusBadge(status) {
  return el("span", { class: "badge " + status }, status);
}

function renderPackages(packages) {
  const list = $("#package-list");
  list.replaceChildren();
  if (!packages.length) {
    list.append(el("p", { class: "muted small" }, "尚无数据包。首次续约或点击“按当前策略重建包”会创建。"));
    return;
  }
  for (const pkg of packages) {
    const row = el("div", { class: "package" },
      el("div", { class: "pkey" }, pkg.package_key),
      el("div", { class: "prow" },
        statusBadge(pkg.status),
        el("span", { class: "muted small" }, `policy v${pkg.policy_version} · ${pkg.allowed_fields.length} fields · ${fmtBytes(pkg.size_bytes)}`),
        el("button", { class: "linklike", type: "button", onclick: () => openBasis(pkg.id) }, "授权依据 →"),
      ),
      pkg.status === "ready" ? el("div", { class: "note", html:
        `sha256 <span class="mono">${shortHash(pkg.content_sha256)}</span> · ${pkg.row_count} rows · ${fmtTime(pkg.ready_at)}` }) : null,
      pkg.status === "retired" ? el("div", { class: "note" }, "已退休：工件保留用于审计，下载边缘不提供。") : null,
      pkg.failure_reason ? el("div", { class: "note" }, "失败：" + pkg.failure_reason) : null,
    );
    list.append(row);
  }
}

function renderContracts(contracts) {
  const wrap = $("#contract-table");
  wrap.replaceChildren();
  if (!contracts.length) {
    wrap.append(el("p", { class: "muted small" }, "尚无合约。消费端调用 /consumer/v1/renew 后会生成。"));
    return;
  }
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      el("th", {}, "消费者"), el("th", {}, "版本"), el("th", {}, "状态"),
      el("th", {}, "变更"), el("th", {}, "允许字段"), el("th", {}, "包"), el("th", {}, "生效"))),
  );
  const body = el("tbody");
  for (const contract of contracts) {
    body.append(el("tr", {},
      el("td", {}, el("strong", {}, contract.consumer_id)),
      el("td", { class: "mono" }, `v${contract.version}`),
      el("td", {}, el("span", { class: "badge " + (contract.status === "active" ? "ready" : "retired") }, contract.status),
        contract.renewal_required ? el("span", { class: "badge pending" }, "需续约") : null),
      el("td", { class: "small" }, contract.change_kind),
      el("td", {}, contract.allowed_fields.map((f) => el("span", { class: "chip kept" }, f))),
      el("td", { class: "mono small" }, contract.package_key || "—"),
      el("td", { class: "small muted" }, fmtTime(contract.effective_at)),
    ));
  }
  table.append(body);
  wrap.append(table);
}

function renderActivity(data) {
  const box = $("#activity");
  box.replaceChildren();
  // Activity is derived from the most recently inspected package basis.
  const recent = (state.basisCache && state.basisCache[data.purpose.code]) || null;
  if (recent) {
    box.append(renderEvents("下载事件", recent.download_events || [], (e) => `${e.event} · ${e.node_id} · ${fmtBytes(e.bytes)}`, (e) => e.detail));
    box.append(renderEvents("确认", recent.acks || [], (a) => `${a.consumer_id} · ${a.classification}`, (a) => a.detail));
  } else {
    box.append(el("div", {},
      el("h3", {}, "下载与确认"),
      el("p", { class: "muted small" }, "打开任一包的“授权依据”查看逐次下载事件、确认分类与合约/策略来源。"),
    ));
  }
}

function renderEvents(title, rows, head, detail) {
  const box = el("div", {}, el("h3", {}, title));
  if (!rows.length) {
    box.append(el("p", { class: "muted small" }, "无记录"));
    return box;
  }
  for (const row of rows.slice(0, 8)) {
    box.append(el("div", { class: "event" },
      el("div", {}, el("div", {}, head(row)), el("div", { class: "detail" }, detail(row) || "")),
      el("span", { class: "when" }, (row.at || row.received_at || "").slice(11, 19)),
    ));
  }
  return box;
}

function openEditor() {
  const data = state.detail;
  if (!data) return;
  $("#editor").hidden = false;
  $("#editor-title").textContent = `${data.purpose.name} · 字段调整`;
  $("#editor-note").value = "";
  const grid = $("#editor-fields");
  grid.replaceChildren();
  const allowed = new Set(data.allowed_fields);
  for (const field of data.field_catalog) {
    const isAllowed = allowed.has(field.field);
    const checkbox = el("input", { type: "checkbox" });
    checkbox.checked = isAllowed;
    checkbox.disabled = !isAllowed;
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.editing.add(field.field);
      else state.editing.delete(field.field);
      $("#apply-btn").disabled = true;
      state.preview = null;
    });
    const card = el("label", { class: "field-card " + (isAllowed ? "allowed" : "denied") },
      el("div", {}, checkbox, el("span", { class: "fname" }, field.field), " ",
        el("span", { class: "sens " + field.sensitivity }, field.sensitivity)),
      el("div", { class: "fmeta" }, `${field.category} · ${field.description}`),
    );
    grid.append(card);
  }
  $("#preview-result").replaceChildren();
  $("#apply-btn").disabled = true;
}

async function previewPolicy() {
  const note = $("#editor-note").value.trim();
  const fields = [...state.editing];
  const button = $("#preview-btn");
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> 预览中';
  try {
    const preview = await api(`/api/v1/admin/purposes/${encodeURIComponent(state.selected)}/preview`, {
      method: "POST",
      body: JSON.stringify({ fields, note }),
    });
    state.preview = preview;
    renderPreview(preview);
    $("#apply-btn").disabled = preview.removed_fields.length === 0;
  } catch (error) {
    $("#preview-result").replaceChildren(el("div", { class: "callout" }, error.message));
    $("#apply-btn").disabled = true;
  } finally {
    button.disabled = false;
    button.textContent = "预览影响";
  }
}

function renderPreview(preview) {
  const box = $("#preview-result");
  box.replaceChildren();
  const removed = preview.removed_fields;
  const affected = preview.affected;
  box.append(el("div", { class: "preview-card" },
    el("h3", {}, "字段变化"),
    el("div", {},
      preview.proposed.fields.map((f) => el("span", { class: "chip kept" }, f)),
      removed.map((r) => el("span", { class: "chip removed", title: r.reason }, r.field)),
    ),
    el("p", { class: "muted small", style: "margin-top:6px" },
      removed.length
        ? `移除 ${removed.length} 个字段，将创建策略 v${preview.proposed.would_create_policy_version}。`
        : "没有字段变化。"),
  ));
  box.append(el("div", { class: "preview-card" },
    el("h3", {}, "影响范围"),
    el("dl", { class: "kv" },
      el("dt", {}, "受影响订阅"), el("dd", {}, String(affected.subscriptions)),
      el("dt", {}, "当前活跃合约"), el("dd", {}, String(affected.active_contracts)),
      el("dt", {}, "失去字段的合约"), el("dd", {}, String(affected.contracts_losing_fields.length)),
      el("dt", {}, "将吊销的授权"), el("dd", {}, String(affected.grants_to_revoke)),
      el("dt", {}, "在途下载"), el("dd", {}, String(affected.active_download_sessions)),
      el("dt", {}, "将退休的旧包"), el("dd", {}, String(affected.packages_retired)),
      el("dt", {}, "新包规模"), el("dd", {}, `约 ${fmtBytes(preview.new_package.estimated_size_bytes)} / ${preview.new_package.estimated_rows} rows`),
    ),
  ));
  if (affected.contracts_losing_fields.length) {
    const card = el("div", { class: "preview-card" }, el("h3", {}, "将失去字段的合约"));
    for (const contract of affected.contracts_losing_fields) {
      card.append(el("div", { class: "small" },
        `${contract.consumer_id} · contract v${contract.version}: `,
        contract.fields.map((f) => el("span", { class: "chip removed" }, f)),
      ));
    }
    card.append(el("p", { class: "muted small", style: "margin-top:6px" },
      "这些合约的现有授权会立即吊销；消费端必须在续约后才能继续下载。"));
    box.append(card);
  }
  box.append(el("div", { class: "callout" },
    "应用后：新策略版本生效，旧包退休并保留审计，新包排队构建；边缘缓存会在下一次巡检时清除旧包，任何在途下载会在下一个复核间隔被切断。"));
}

async function applyPolicy() {
  if (!state.preview) return;
  const button = $("#apply-btn");
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> 应用中';
  try {
    const fields = [...state.editing];
    const result = await api(`/api/v1/admin/purposes/${encodeURIComponent(state.selected)}/policy`, {
      method: "POST",
      body: JSON.stringify({ fields, note: $("#editor-note").value.trim() }),
    });
    toast(`策略 v${result.policy_version} 已生效；吊销 ${result.revoked_grants} 个授权，包 ${result.package.package_key} 构建中`);
    $("#editor").hidden = true;
    state.preview = null;
    await loadOverview();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "确认并重建";
  }
}

async function rebuild() {
  const button = $("#rebuild");
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> 排队中';
  try {
    const result = await api(`/api/v1/admin/purposes/${encodeURIComponent(state.selected)}/rebuild`, {
      method: "POST", body: JSON.stringify({ force: true }),
    });
    toast(result.status === "already_ready" ? "包已就绪，无需重建" : `已排队：${result.package.package_key}`);
    await loadOverview();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "按当前策略重建包";
  }
}

async function openBasis(packageId) {
  const drawer = $("#basis");
  drawer.hidden = false;
  const content = $("#basis-content");
  content.replaceChildren(el("p", { class: "muted" }, "加载中…"));
  try {
    const data = await api(`/api/v1/admin/packages/${packageId}`);
    const pkg = data.package;
    const basis = pkg.authorization_basis;
    content.replaceChildren();
    content.append(el("div", { class: "basis-package" },
      el("h3", {}, pkg.package_key),
      el("dl", { class: "kv" },
        el("dt", {}, "包状态"), el("dd", {}, statusBadge(pkg.status)),
        el("dt", {}, "用途"), el("dd", {}, `${basis.purpose.name} (${basis.purpose.code})`),
        el("dt", {}, "策略版本"), el("dd", {}, `v${basis.policy.version} · ${basis.policy.status}`),
        el("dt", {}, "策略哈希"), el("dd", { class: "mono" }, basis.policy.policy_hash),
        el("dt", {}, "策略说明"), el("dd", {}, basis.policy.note || "—"),
        el("dt", {}, "字段集哈希"), el("dd", { class: "mono" }, pkg.fields_hash),
        el("dt", {}, "内容 sha256"), el("dd", { class: "mono" }, pkg.content_sha256 || "—"),
        el("dt", {}, "清单签名"), el("dd", { class: "mono" }, pkg.signature ? shortHash(pkg.signature) : "—"),
        el("dt", {}, "行数 / 大小"), el("dd", {}, `${pkg.row_count ?? "—"} / ${fmtBytes(pkg.size_bytes)}`),
        el("dt", {}, "保留说明"), el("dd", {}, pkg.retention_note || "—"),
      ),
    ));
    const rules = el("div", { class: "basis-section" }, el("h4", {}, "策略规则（授权依据）"));
    for (const rule of basis.rules.filter((r) => r.allowed === 1)) {
      rules.append(el("span", { class: "chip kept" }, `${rule.field}: ${rule.reason}`));
    }
    for (const rule of basis.rules.filter((r) => r.allowed === 0).slice(0, 8)) {
      rules.append(el("span", { class: "chip" }, `${rule.field}: ${rule.reason}`));
    }
    content.append(rules);

    if (basis.contracts.length) {
      const section = el("div", { class: "basis-section" }, el("h4", {}, "引用此包的合约"));
      const table = el("table", {}, el("thead", {}, el("tr", {},
        el("th", {}, "消费者"), el("th", {}, "版本"), el("th", {}, "状态"), el("th", {}, "允许字段"), el("th", {}, "生效"))));
      const body = el("tbody");
      for (const c of basis.contracts) {
        body.append(el("tr", {},
          el("td", { class: "mono" }, c.consumer_id),
          el("td", { class: "mono" }, `v${c.version}`),
          el("td", {}, c.status),
          el("td", {}, c.allowed_fields.map((f) => el("span", { class: "chip kept" }, f))),
          el("td", { class: "small muted" }, fmtTime(c.effective_at)),
        ));
      }
      table.append(body);
      section.append(table);
      content.append(section);
    }

    content.append(el("div", { class: "basis-section" },
      el("h4", {}, "授权（grant）"),
      basis.grants.length
        ? el("pre", { class: "json" }, JSON.stringify(basis.grants, null, 2))
        : el("p", { class: "muted small" }, "尚无授权记录"),
    ));
    content.append(el("div", { class: "basis-section" },
      el("h4", {}, "下载事件"),
      basis.download_events.length
        ? el("pre", { class: "json" }, JSON.stringify(basis.download_events, null, 2))
        : el("p", { class: "muted small" }, "尚无下载事件"),
    ));
    content.append(el("div", { class: "basis-section" },
      el("h4", {}, "消费端确认（重复提交已去重；旧确认保留但不计入当前）"),
      basis.acks.length
        ? el("pre", { class: "json" }, JSON.stringify(basis.acks, null, 2))
        : el("p", { class: "muted small" }, "尚无确认"),
    ));
    content.append(el("div", { class: "basis-section" },
      el("h4", {}, "清单 manifest"),
      el("pre", { class: "json" }, JSON.stringify(pkg.manifest, null, 2)),
    ));
    if (state.detail) {
      state.basisCache = state.basisCache || {};
      state.basisCache[state.detail.purpose.code] = { download_events: basis.download_events, acks: basis.acks };
      renderActivity(state.detail);
    }
  } catch (error) {
    content.replaceChildren(el("div", { class: "callout" }, error.message));
  }
}

function bind() {
  document.querySelectorAll("[data-close]").forEach((node) => {
    node.addEventListener("click", () => { node.closest(".drawer").hidden = true; });
  });
  $("#refresh").addEventListener("click", () => loadOverview().catch((e) => toast(e.message, true)));
  $("#open-editor").addEventListener("click", openEditor);
  $("#preview-btn").addEventListener("click", previewPolicy);
  $("#apply-btn").addEventListener("click", applyPolicy);
  $("#rebuild").addEventListener("click", rebuild);
  $("#open-basis").addEventListener("click", () => {
    const pkg = state.detail?.packages?.find((p) => p.status === "ready");
    if (!pkg) return toast("当前没有可追溯的就绪包", true);
    openBasis(pkg.id);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      $("#editor").hidden = true;
      $("#basis").hidden = true;
    }
  });
}

async function boot() {
  bind();
  try {
    const overview = await loadOverview();
    if (state.purposes.length) await selectPurpose(state.purposes[0].code);
    state.pollTimer = setInterval(() => {
      if (document.hidden) return;
      loadOverview().catch(() => {});
    }, 5000);
  } catch (error) {
    $("#health-pill").textContent = "registry 不可用";
    $("#health-pill").className = "pill bad";
    toast(error.message, true);
  }
}

boot();
