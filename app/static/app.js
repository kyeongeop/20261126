"use strict";

const $ = (id) => document.getElementById(id);
const state = { lastQuery: "", lastData: null };

const EXAMPLES = [
  'level = "error"',
  '#deploy AND NOT #verified',
  'level = "error" AFTER #deploy WITHIN 30m',
  '#timeout BEFORE #rollback WITHIN 60m',
  'all_tags("db-lock", "timeout")',
  'LAST 2h AND level = "error"',
  'message ~ "timeout"',
];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function showError(error) {
  const panel = $("error-panel");
  panel.classList.remove("hidden");
  $("error-kind").textContent = error.kind === "semantic" ? "语义错误" : "语法错误";
  $("error-message").textContent = error.message;
  const loc = error.line
    ? `第 ${error.line} 行 · 第 ${error.column} 列${error.fragment ? ` · 片段 “${error.fragment}”` : ""}`
    : "";
  $("error-loc").textContent = loc;
  $("error-rendered").textContent = error.rendered || "";
}

function clearError() {
  $("error-panel").classList.add("hidden");
  $("error-rendered").textContent = "";
}

function levelBadge(level) {
  return `<span class="level ${escapeHtml(level)}">${escapeHtml(level)}</span>`;
}

function renderRows(items) {
  const body = $("result-body");
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">没有匹配的事件。可放宽时间窗口或检查拼写（语法错误会精确定位到列）。</td></tr>';
    return;
  }
  body.innerHTML = items.map((ev) => {
    const tags = (ev.tags || []).map((t) => `<span class="tag">#${escapeHtml(t)}</span>`).join("");
    const evidence = (ev.evidence || []).map((e) => {
      const label = `[${escapeHtml(e.kind)}] ${escapeHtml(e.label)}`;
      if (e.ref && /^https?:\/\//.test(e.ref)) {
        return `<div class="ev-item">• <a href="${escapeHtml(e.ref)}" target="_blank" rel="noopener">${label}</a></div>`;
      }
      return `<div class="ev-item">• ${label}${e.ref ? ` <span class="ev-ref">${escapeHtml(e.ref)}</span>` : ""}</div>`;
    }).join("");
    return `<tr>
      <td class="ts">${escapeHtml(ev.ts)}<div class="ev-ref">#${ev.id}</div></td>
      <td class="host">${escapeHtml(ev.host)}</td>
      <td>${escapeHtml(ev.service)}</td>
      <td>${levelBadge(ev.level)}</td>
      <td class="msg">${escapeHtml(ev.message)}</td>
      <td>${tags}</td>
      <td class="evidence-cell">${evidence || '<span class="ev-ref">—</span>'}</td>
    </tr>`;
  }).join("");
}

function renderSummary(data) {
  state.lastData = data;
  const trunc = data.truncated
    ? `<span class="trunc">结果已截断：仅显示前 ${data.returned} 条（共匹配 ${data.total} 条），可缩小条件或导出。</span>`
    : "";
  const clamp = data.clamped ? `<span class="trunc">limit 超过上限 ${data.max_limit}，已按上限返回。</span>` : "";
  $("result-summary").innerHTML =
    `匹配 <b>${data.total}</b> 条 · 返回 <b>${data.returned}</b> 条${trunc}${clamp}`;
  $("active-query").textContent = data.query ? `TQL> ${data.query}` : "TQL> (空，全部事件)";
  renderRows(data.items);
}

function currentParams() {
  return {
    q: $("tql-input").value,
    limit: Number($("limit-input").value || 100),
    order: $("order-select").value,
  };
}

async function runQuery() {
  clearError();
  const params = currentParams();
  state.lastQuery = params.q;
  const url = "/api/timeline/query?" + new URLSearchParams({
    q: params.q, limit: String(params.limit), order: params.order,
  });
  const resp = await fetch(url);
  const data = await resp.json();
  if (!resp.ok) {
    if (data.error) { showError(data.error); }
    $("result-summary").textContent = "查询失败";
    return;
  }
  renderSummary(data);
}

function exportUrl(format) {
  const params = currentParams();
  return "/api/timeline/export?" + new URLSearchParams({
    q: params.q, format, limit: String(Math.max(params.limit, 1000)), order: params.order,
  });
}

async function loadHosts() {
  try {
    const resp = await fetch("/api/hosts");
    const data = await resp.json();
    const select = $("host-select");
    data.hosts.forEach((h) => {
      const opt = document.createElement("option");
      opt.value = h.host;
      opt.textContent = `${h.host} (${h.count})`;
      select.appendChild(opt);
    });
  } catch (_) { /* 忽略元数据加载失败 */ }
}

async function checkHealth() {
  try {
    const resp = await fetch("/api/health");
    const data = await resp.json();
    const badge = $("db-status");
    badge.textContent = data.status === "ok" ? "本地 SQLite · 在线" : "异常";
    badge.classList.add("ok");
  } catch (_) {
    $("db-status").textContent = "服务不可用";
  }
}

function runClassic() {
  const host = $("host-select").value;
  const startVal = $("start-input").value;
  const params = new URLSearchParams();
  if (host) params.set("host", host);
  if (startVal) params.set("start", new Date(startVal).toISOString());
  fetch("/api/events?" + params.toString())
    .then((r) => r.json())
    .then((data) => {
      clearError();
      $("tql-input").value = "";
      renderSummary({ ...data, query: "", truncated: data.returned < data.total,
        offset: 0, order: "asc" });
    });
}

function syncClassicToTql() {
  const parts = [];
  const host = $("host-select").value;
  const startVal = $("start-input").value;
  if (host) parts.push(`host = "${host}"`);
  if (startVal) parts.push(`ts >= "${new Date(startVal).toISOString()}"`);
  $("tql-input").value = parts.join(" AND ");
}

function initExamples() {
  const box = $("examples");
  EXAMPLES.forEach((q) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip";
    chip.textContent = q;
    chip.addEventListener("click", () => {
      $("tql-input").value = q;
      runQuery();
    });
    box.appendChild(chip);
  });
}

window.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  loadHosts();
  initExamples();
  $("btn-run").addEventListener("click", runQuery);
  $("btn-classic").addEventListener("click", runClassic);
  $("btn-sync-tql").addEventListener("click", syncClassicToTql);
  $("btn-export-csv").addEventListener("click", () => { window.location.href = exportUrl("csv"); });
  $("btn-export-json").addEventListener("click", () => { window.location.href = exportUrl("json"); });
  $("tql-input").addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runQuery();
  });
  runQuery();
});
