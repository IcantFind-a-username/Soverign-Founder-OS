"use strict";
let lang = localStorage.getItem("sovereign-ui-lang")
  || (navigator.language && navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en");
let view = localStorage.getItem("sovereign-ui-view") || "command";
let lastState = null;
let lastGauntlet = null;
let lastCommand = null;
let ws = null;

const $ = (id) => document.getElementById(id);
const t = (key) => STRINGS[lang][key];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badge(kind, label) {
  const marks = { good: "✓ ", bad: "✗ ", warn: "⧗ ", neutral: "" };
  return el("span", "badge " + kind, (marks[kind] || "") + label);
}

function table(headers, rows) {
  const tbl = el("table");
  const thead = el("thead"); const hr = el("tr");
  headers.forEach(h => hr.appendChild(el("th", null, h)));
  thead.appendChild(hr); tbl.appendChild(thead);
  const tbody = el("tbody");
  rows.forEach(cells => {
    const tr = el("tr");
    cells.forEach(cell => {
      if (cell instanceof Node) { const td = el("td"); td.appendChild(cell); tr.appendChild(td); }
      else { tr.appendChild(el("td", cell && cell.mono ? "mono" : null, cell && cell.mono ? cell.mono : cell)); }
    });
    tbody.appendChild(tr);
  });
  tbl.appendChild(tbody);
  return tbl;
}

const locale = () => lang === "zh" ? "zh-CN" : undefined;
const fmtTime = (unix) => new Date(unix * 1000).toLocaleString(locale());

async function api(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ lang }, body || {})),
  });
  return response.json();
}

// Visible, consistent feedback for every action: successes confirm what was
// signed, and errors are never swallowed or shown far from where they happened.
function toast(kind, message) {
  const node = el("div", "toast " + kind, message);
  node.addEventListener("click", () => node.remove());
  $("toasts").appendChild(node);
  setTimeout(() => {
    node.classList.add("out");
    setTimeout(() => node.remove(), 260);
  }, 4500);
}

// Double-submit protection: while an action is in flight its button is
// disabled, so an impatient double-click can never create two documents or
// race two decisions.
async function withBusy(button, fn) {
  if (button.disabled) return;
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}

// Signed decisions are permanent: every irreversible action passes through
// this dialog, which states exactly what will happen before it happens.
function confirmAction(kind, subject) {
  return new Promise((resolve) => {
    const dialog = $("confirm-dialog");
    $("confirm-title").textContent = t("confirm_" + kind + "_title");
    $("confirm-body").textContent = t("confirm_" + kind + "_body")(subject || "");
    const finish = (ok, close) => {
      $("confirm-ok").removeEventListener("click", onOk);
      $("confirm-cancel").removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onEsc);
      if (close) dialog.close();
      resolve(ok);
    };
    const onOk = () => finish(true, true);
    const onCancel = () => finish(false, true);
    const onEsc = () => finish(false, false);
    $("confirm-ok").addEventListener("click", onOk);
    $("confirm-cancel").addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onEsc);
    dialog.showModal();
  });
}

/* ─────────────── Workspace ─────────────── */

async function loadWorkspace() {
  const data = await (await fetch("/api/workspace")).json();
  if (data.ok) { ws = data.workspace; renderWorkspace(); }
}

function renderWorkspace() {
  if (!ws) return;
  if (ws.venture) {
    if (document.activeElement !== $("v-name")) $("v-name").value = ws.venture.name;
    if (document.activeElement !== $("v-service")) $("v-service").value = ws.venture.service;
  }

  const customers = $("customers");
  if (!ws.customers.length) {
    customers.replaceChildren(el("div", "empty", t("ws_no_customers")));
  } else {
    customers.replaceChildren(table(
      [t("th_customer"), t("th_email"), t("th_notes"), t("th_added")],
      ws.customers.map(c => [c.name, c.email || "—", c.notes, fmtTime(c.created_at)])));
  }

  const select = $("d-customer");
  const selected = select.value;
  select.replaceChildren(...ws.customers.map(c => {
    const option = el("option", null, c.name);
    option.value = c.id;
    return option;
  }));
  if (selected && ws.customers.some(c => c.id === selected)) select.value = selected;

  const documents = $("documents");
  if (!ws.documents.length) {
    documents.replaceChildren(el("div", "empty", t("ws_no_documents")));
  } else {
    documents.replaceChildren(...[...ws.documents].reverse().map(d => {
      const wrap = el("div", "doc");
      const head = el("div", "doc-head");
      head.appendChild(el("span", "badge neutral", t(d.kind === "offer" ? "kind_offer" : "kind_invoice")));
      head.appendChild(el("span", "title", d.title));
      const statusKind = { draft: "neutral", pending_approval: "warn", approved_pending_delivery: "good", rejected: "bad", revoked: "neutral", delivered: "good" }[d.status] || "neutral";
      head.appendChild(badge(statusKind, t("status_" + d.status)));
      if (d.status === "draft") {
        const submit = el("button", "ghost small", t("ws_submit_send"));
        submit.addEventListener("click", () => withBusy(submit, async () => {
          const result = await api("/api/workspace/request-send", { document_id: d.id });
          if (result.ok) { ws = result.workspace; renderWorkspace(); }
          else toast("bad", result.error);
        }));
        head.appendChild(submit);
      }
      if (d.status === "approved_pending_delivery") {
        const delivered = el("button", "ghost small", t("ws_mark_delivered"));
        delivered.addEventListener("click", () => withBusy(delivered, async () => {
          if (!await confirmAction("deliver", d.title)) return;
          const result = await api("/api/workspace/confirm-delivery", { document_id: d.id });
          if (result.ok) { ws = result.workspace; renderWorkspace(); loadState(); toast("good", t("toast_delivered")(d.title)); }
          else toast("bad", result.error);
        }));
        head.appendChild(delivered);
        const revoke = el("button", "ghost small", t("ws_revoke"));
        revoke.addEventListener("click", () => withBusy(revoke, async () => {
          if (!await confirmAction("revoke", d.title)) return;
          const result = await api("/api/workspace/revoke", { document_id: d.id });
          if (result.ok) { ws = result.workspace; renderWorkspace(); loadState(); toast("good", t("toast_revoked")(d.title)); }
          else toast("bad", result.error);
        }));
        head.appendChild(revoke);
      }
      wrap.appendChild(head);
      const approvalWithEvidence = ws.approvals.find(a => a.document_id === d.id && a.evidence);
      if (approvalWithEvidence) {
        wrap.appendChild(el("div", "mono", t("ws_evidence")(approvalWithEvidence.evidence)));
        if (approvalWithEvidence.evidence.outbox) {
          wrap.appendChild(el("div", "mono", t("ws_outbox")(approvalWithEvidence.evidence.outbox)));
        }
      }
      const details = el("details");
      details.appendChild(el("summary", null, t("ws_view_content")));
      details.appendChild(el("pre", null, d.body));
      wrap.appendChild(details);
      return wrap;
    }));
  }

  const approvals = $("approvals");
  const pending = ws.approvals.filter(a => a.status === "pending");
  if (!pending.length) {
    approvals.replaceChildren(el("div", "empty", t("ws_no_approvals")));
  } else {
    approvals.replaceChildren(...pending.map(a => {
      const doc = ws.documents.find(d => d.id === a.document_id);
      const row = el("div", "approval");
      const info = el("div");
      info.appendChild(el("div", null, t("ws_approval_for") + (doc ? doc.title : a.document_id)));
      info.appendChild(el("div", "why", a.policy_reason));
      row.appendChild(info);
      const actions = el("div", "actions");
      const approve = el("button", "approve", "✓ " + t("ws_approve"));
      const reject = el("button", "reject", "✗ " + t("ws_reject"));
      const decide = async (yes) => {
        const title = doc ? doc.title : a.document_id;
        if (!await confirmAction(yes ? "approve" : "reject", title)) return;
        const result = await api("/api/workspace/decide", { approval_id: a.id, approve: yes });
        if (result.ok) {
          ws = result.workspace; renderWorkspace(); loadState();
          toast("good", t(yes ? "toast_approved" : "toast_rejected")(title));
        } else {
          toast("bad", result.error);
        }
      };
      approve.addEventListener("click", () => withBusy(approve, () => decide(true)));
      reject.addEventListener("click", () => withBusy(reject, () => decide(false)));
      actions.appendChild(approve); actions.appendChild(reject);
      row.appendChild(actions);
      return row;
    }));
  }
}

async function saveVenture() {
  const result = await api("/api/workspace/venture", { name: $("v-name").value, service: $("v-service").value });
  $("v-status").textContent = result.ok ? t("saved") : "";
  if (result.ok) { ws = result.workspace; renderWorkspace(); loadState(); }
  else toast("bad", result.error);
}

async function addCustomer() {
  const result = await api("/api/workspace/customer", { name: $("c-name").value, email: $("c-email").value, notes: $("c-notes").value });
  if (result.ok) { $("c-name").value = ""; $("c-email").value = ""; $("c-notes").value = ""; ws = result.workspace; renderWorkspace(); loadState(); }
  else toast("bad", result.error);
}

async function draftAssist() {
  const customer_id = $("d-customer").value;
  if (!customer_id) { $("d-status").textContent = t("ws_no_customers"); return; }
  $("d-status").textContent = "…";
  const result = await api("/api/workspace/assist", { customer_id });
  if (!result.ok) { $("d-status").textContent = ""; toast("bad", result.error); return; }
  $("d-status").textContent = "";
  const s = result.suggestion;
  $("assist-box").hidden = false;
  $("assist-label").textContent = t("ws_assist_label");
  $("assist-text").value = s.text;
  $("assist-meta").textContent = t("ws_assist_meta")(s);
  loadState();
}

async function createDocument(kind) {
  const body = { customer_id: $("d-customer").value };
  if (kind === "invoice") body.amount = $("d-amount").value;
  const result = await api("/api/workspace/" + kind, body);
  $("d-status").textContent = result.ok ? t("saved") : "";
  if (result.ok) { ws = result.workspace; renderWorkspace(); loadState(); }
  else toast("bad", result.error);
}

/* ─────────────── Security Center ─────────────── */

function renderState() {
  const state = lastState;
  if (!state) return;
  $("t-device").textContent = state.device_id ? t("device_ready") : t("device_none");
  $("t-device-meta").textContent = state.device_id || t("device_hint");
  $("t-events").textContent = state.ledger.count;
  $("t-chain").replaceChildren(
    state.ledger.present
      ? badge(state.ledger.chain_ok ? "good" : "bad", state.ledger.chain_ok ? t("chain_ok") : t("chain_broken"))
      : el("span", null, t("no_ledger_tile")));
  $("t-vault").textContent = state.vault_entries.length;
  $("t-plugins").textContent = state.plugins.length;

  const integrity = $("integrity");
  const ir = state.integrity;
  if (!ir) {
    integrity.replaceChildren(el("div", "empty", t("loading")));
  } else {
    const wrap = el("div", null);
    const head = el("div", "gauntlet-row");
    head.appendChild(badge(ir.ok ? "good" : "bad", ir.ok ? t("integrity_ok") : t("integrity_bad")));
    head.appendChild(document.createTextNode(" " + t("integrity_summary")(ir.chain_verified, ir.events)));
    wrap.appendChild(head);
    if (ir.error) wrap.appendChild(el("div", "mono", ir.error));
    (ir.findings || []).forEach(f => {
      const row = el("div", "gauntlet-row");
      row.appendChild(badge("bad", f.severity));
      row.appendChild(el("div", "detail", f.resource + " — " + f.detail));
      wrap.appendChild(row);
    });
    wrap.classList.remove("empty");
    integrity.replaceChildren(wrap);
    integrity.classList.remove("empty");
  }

  const disclosures = $("disclosures");
  const dl = state.disclosures || [];
  if (!dl.length) {
    disclosures.replaceChildren(el("div", "empty", t("disclosures_empty")));
  } else {
    disclosures.replaceChildren(table(
      [t("th_time"), t("th_customer"), t("th_provider"), t("th_where"), t("th_class"), t("th_failover")],
      dl.map(d => [
        new Date(d.at * 1000).toLocaleString(locale()),
        d.customer,
        d.provider + " (" + d.provider_trust + ")",
        d.stayed_local ? badge("good", t("stayed_local")) : badge("warn", t("left_device")),
        d.data_class,
        d.failover_from.length ? d.failover_from.join(", ") : "—",
      ])));
    disclosures.classList.remove("empty");
  }

  const plugins = $("plugins");
  if (!state.plugins.length) {
    plugins.replaceChildren(el("div", "empty", t("plugins_empty")));
  } else {
    plugins.replaceChildren(table(
      [t("th_status"), t("th_component"), t("th_manifest"), t("th_risk"), t("th_backend"), t("th_admitted_by")],
      state.plugins.map(p => p.verified
        ? [badge("good", t("verified")), {mono: p.component_digest + "…"}, {mono: p.manifest_digest + "…"},
           String(p.risk_class), String(p.backend), p.issuer]
        : [badge("bad", t("unverified")), {mono: p.manifest_digest + "…"}, "", "", "", p.error])));
  }

  const ledger = $("ledger");
  if (!state.ledger.present || (state.ledger.chain_ok && !state.ledger.events.length)) {
    ledger.replaceChildren(el("div", "empty", t("ledger_empty")));
  } else if (!state.ledger.chain_ok) {
    const wrap = el("div", "empty");
    wrap.appendChild(badge("bad", t("ledger_broken")));
    wrap.appendChild(el("div", "mono", state.ledger.error || ""));
    ledger.replaceChildren(wrap);
  } else {
    ledger.replaceChildren(table(
      [t("th_time"), t("th_actor"), t("th_action"), t("th_resource"), t("th_hash")],
      state.ledger.events.map(e =>
        [new Date(e.timestamp).toLocaleString(locale()), e.actor, e.action, e.resource, {mono: e.hash + "…"}])));
  }
}

function renderGauntlet() {
  if (!lastGauntlet) return;
  const box = $("gauntlet");
  box.classList.remove("empty");
  box.replaceChildren(...lastGauntlet.map(r => {
    const localized = STRINGS[lang].attacks[r.key];
    const row = el("div", "gauntlet-row");
    const name = el("div", "name");
    name.appendChild(badge(r.pass ? "good" : "bad", r.pass ? t("held") : t("failed")));
    name.appendChild(document.createTextNode(" " + (localized ? localized.name : r.name)));
    row.appendChild(name);
    row.appendChild(el("div", "detail", localized ? localized.detail : r.detail));
    return row;
  }));
  const failed = lastGauntlet.filter(r => !r.pass).length;
  $("gauntlet-status").textContent = failed ? t("violated")(failed) : t("all_held")(lastGauntlet.length);
}

async function loadState() {
  try {
    lastState = await (await fetch("/api/state")).json();
    renderState();
  } catch (error) {
    $("stage") && ($("stage").textContent = t("state_failed") + error);
  }
}

async function runGauntlet() {
  const button = $("run");
  button.disabled = true;
  $("gauntlet-status").textContent = t("running");
  try {
    const data = await api("/api/gauntlet");
    if (!data.ok) {
      $("gauntlet").replaceChildren(el("div", "empty", t("gauntlet_error") + data.error));
    } else {
      lastGauntlet = data.results;
      renderGauntlet();
    }
  } catch (error) {
    $("gauntlet-status").textContent = t("request_failed") + error;
  } finally {
    button.disabled = false;
  }
}

/* ─────────────── Backup verification ─────────────── */

async function verifyBackup() {
  const input = $("verify-file");
  const status = $("verify-status");
  const reportBox = $("verify-report");
  const file = input.files && input.files[0];
  if (!file) { status.textContent = t("ws_verify_pick"); return; }
  status.textContent = t("ws_verify_reading");
  reportBox.hidden = true;
  let bundle;
  try {
    bundle = JSON.parse(await file.text());
  } catch (error) {
    status.textContent = t("ws_verify_badfile");
    return;
  }
  status.textContent = t("ws_verify_checking");
  try {
    const data = await api("/api/verify-export", { bundle });
    if (!data.ok) { status.textContent = data.error || t("ws_verify_fail"); return; }
    status.textContent = "";
    renderVerifyReport(data.report);
  } catch (error) {
    status.textContent = t("request_failed") + error;
  }
}

function renderVerifyReport(r) {
  const box = $("verify-report");
  box.hidden = false;
  const mark = (ok) => badge(ok ? "good" : "bad", ok ? t("ws_verify_pass_word") : t("ws_verify_fail_word"));
  const chain = el("span");
  chain.appendChild(mark(r.audit_chain_verified));
  chain.appendChild(document.createTextNode(" · " + t("ws_verify_events")(r.audit_events)));
  const rows = [
    [t("ws_verify_row_format"), mark(r.format_ok)],
    [t("ws_verify_row_identity"), mark(r.identity_bound)],
    [t("ws_verify_row_chain"), chain],
    [t("ws_verify_row_state"), el("span", null, t("ws_verify_state")(r))],
    [t("ws_verify_device"), el("span", "mono", r.device_id || "—")],
  ];
  const verdict = el("div");
  verdict.appendChild(badge(r.ok ? "good" : "bad", r.ok ? t("ws_verify_pass") : t("ws_verify_fail")));
  const children = [verdict];
  rows.forEach(([label, node]) => {
    const row = el("div", "toolbar");
    row.appendChild(el("span", "status-line", label));
    row.appendChild(node);
    children.push(row);
  });
  (r.notes || []).forEach(note => children.push(el("div", "status-line", "• " + note)));
  box.replaceChildren(...children);
}

/* ─────────────── Command Center ─────────────── */

async function loadCommandCenter() {
  try {
    lastCommand = await (await fetch("/api/command-center")).json();
    renderCommandCenter();
  } catch (error) { /* leave placeholders; other views still work */ }
}

function renderCommandCenter() {
  if (!lastCommand || !lastCommand.ok) return;
  const s = lastCommand.summary;
  const k = lastCommand.kernel;

  const vbox = $("cc-venture");
  if (s.venture) {
    const line = el("div", "venture-line", s.venture.name + " ");
    line.appendChild(el("span", "svc", "· " + s.venture.service));
    vbox.replaceChildren(line);
  } else {
    vbox.replaceChildren(el("span", "empty", t("cc_no_venture")));
  }

  $("cc-customers").textContent = s.counts.customers;
  $("cc-documents").textContent = s.counts.documents;
  $("cc-documents-meta").textContent = t("cc_documents_meta")(s.counts);
  $("cc-pending").textContent = s.pending_decisions.length;
  $("cc-effects").textContent = s.evidence.outbox_effects;
  $("cc-effects-meta").textContent = t("cc_effects_meta")(s.evidence);

  const chainEl = $("cc-chain");
  if (!k.audit_chain_present) { chainEl.textContent = t("cc_chain_none"); chainEl.style.color = ""; }
  else if (k.audit_chain_ok) { chainEl.textContent = t("cc_chain_verified"); chainEl.style.color = "var(--good)"; }
  else { chainEl.textContent = t("cc_chain_broken"); chainEl.style.color = "var(--critical)"; }
  $("cc-chain-meta").textContent = t("cc_events")(k.audit_events);
  $("cc-signed").textContent = s.evidence.signed_approvals;
  $("cc-disclosures").textContent = k.model_disclosures;
  $("cc-plugins").textContent = k.admitted_plugins;

  renderCommandGuidance(s.guidance);
  renderCommandDecisions(s.pending_decisions);
}

function renderCommandGuidance(items) {
  const box = $("cc-guidance");
  if (!items || !items.length) {
    box.className = "empty";
    box.replaceChildren(document.createTextNode(t("cc_no_guidance")));
    return;
  }
  box.className = "";
  box.replaceChildren(...items.map(g => {
    const row = el("div", "pad");
    const bar = el("div", "toolbar");
    const risk = g.kind_class === "risk";
    bar.appendChild(badge(risk ? "warn" : "neutral", risk ? t("cc_risk_word") : t("cc_step_word")));
    bar.appendChild(el("span", null, t("cc_guidance")(g)));
    row.appendChild(bar);
    return row;
  }));
}

function renderCommandDecisions(decisions) {
  const box = $("cc-decisions");
  if (!decisions.length) {
    box.className = "empty";
    box.replaceChildren(document.createTextNode(t("cc_no_decisions")));
    return;
  }
  box.className = "";
  box.replaceChildren(...decisions.map(d => {
    const row = el("div", "pad");
    row.appendChild(el("div", null, t("cc_decision_line")(d)));
    if (d.policy_reason) row.appendChild(el("div", "status-line", d.policy_reason));
    const bar = el("div", "toolbar");
    const approve = el("button", "primary small", t("cc_approve"));
    approve.addEventListener("click", () => withBusy(approve, () => commandDecide(d.approval_id, true, d.document_title)));
    const reject = el("button", "ghost small", t("cc_reject"));
    reject.addEventListener("click", () => withBusy(reject, () => commandDecide(d.approval_id, false, d.document_title)));
    bar.appendChild(approve);
    bar.appendChild(reject);
    row.appendChild(bar);
    return row;
  }));
}

async function commandDecide(approvalId, approve, title) {
  if (!await confirmAction(approve ? "approve" : "reject", title || "")) return;
  const result = await api("/api/workspace/decide", { approval_id: approvalId, approve });
  if (result.ok) {
    ws = result.workspace; renderWorkspace();
    toast("good", t(approve ? "toast_approved" : "toast_rejected")(title || ""));
  } else {
    toast("bad", result.error);
  }
  await loadCommandCenter();
  await loadState();
}

/* ─────────────── Shell ─────────────── */

function applyLanguage() {
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  $("lang-en").classList.toggle("active", lang === "en");
  $("lang-zh").classList.toggle("active", lang === "zh");
  document.querySelectorAll("[data-i18n]").forEach(node => {
    const value = t(node.dataset.i18n);
    if (typeof value === "string") node.textContent = value;
  });
  renderState();
  renderGauntlet();
  renderWorkspace();
  renderCommandCenter();
}

function setLanguage(next) {
  lang = next;
  localStorage.setItem("sovereign-ui-lang", next);
  applyLanguage();
}

function setView(next) {
  view = next;
  localStorage.setItem("sovereign-ui-view", next);
  $("view-command").hidden = next !== "command";
  $("view-workspace").hidden = next !== "workspace";
  $("view-security").hidden = next !== "security";
  $("tab-command").classList.toggle("active", next === "command");
  $("tab-workspace").classList.toggle("active", next === "workspace");
  $("tab-security").classList.toggle("active", next === "security");
  if (next === "command") loadCommandCenter();
}

$("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("sovereign-ui-theme", next); } catch (e) {}
});
$("lang-en").addEventListener("click", () => setLanguage("en"));
$("lang-zh").addEventListener("click", () => setLanguage("zh"));
$("tab-command").addEventListener("click", () => setView("command"));
$("tab-workspace").addEventListener("click", () => setView("workspace"));
$("tab-security").addEventListener("click", () => setView("security"));
$("v-save").addEventListener("click", () => withBusy($("v-save"), saveVenture));
$("c-add").addEventListener("click", () => withBusy($("c-add"), addCustomer));
$("d-assist").addEventListener("click", () => withBusy($("d-assist"), draftAssist));
$("assist-copy").addEventListener("click", () => {
  const text = $("assist-text").value;
  if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
  else { $("assist-text").select(); document.execCommand("copy"); }
  $("assist-copy").textContent = t("ws_assist_copied");
  setTimeout(() => { $("assist-copy").textContent = t("ws_assist_copy"); }, 1500);
});
$("verify-btn").addEventListener("click", () => withBusy($("verify-btn"), verifyBackup));
$("d-offer").addEventListener("click", () => withBusy($("d-offer"), () => createDocument("offer")));
$("d-invoice").addEventListener("click", () => withBusy($("d-invoice"), () => createDocument("invoice")));
$("run").addEventListener("click", runGauntlet);
$("refresh").addEventListener("click", loadState);

applyLanguage();
setView(view);
loadState();
loadWorkspace();
loadCommandCenter();