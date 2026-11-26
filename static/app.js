"use strict";

const state = {
  status: "pending",
  candidates: [],
  selectedId: null,
  detail: null,
  timeline: [],
};

const $ = (sel) => document.querySelector(sel);

function esc(value) {
  if (value === null || value === undefined || value === "") return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function analystName() {
  return ($("#analyst").value || "").trim() || "analyst";
}

let toastTimer = null;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast${isError ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 3200);
}

async function api(path, options = {}) {
  const opts = { headers: { "Content-Type": "application/json" }, ...options };
  if (opts.body && typeof opts.body !== "string") opts.body = JSON.stringify(opts.body);
  const res = await fetch(path, opts);
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const msg = data.message || data.detail || `请求失败 (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

function confColor(label) {
  return label === "high" ? "var(--high)" : label === "medium" ? "var(--mid)" : "var(--low)";
}

function statusText(status) {
  return { pending: "待处理", merged: "已保留合并", split: "已拆分", unknown: "未知" }[status] || status;
}

async function loadCandidates(selectId) {
  const q = state.status === "all" ? "" : `?status=${encodeURIComponent(state.status)}`;
  state.candidates = await api(`/api/candidates${q}`);
  renderCandidateList();
  if (selectId) state.selectedId = selectId;
  if (!state.selectedId && state.candidates.length) {
    state.selectedId = state.candidates[0].id;
  }
  if (state.selectedId) {
    await loadDetail(state.selectedId);
  } else {
    state.detail = null;
    renderDetail();
  }
}

async function loadDetail(id) {
  try {
    state.detail = await api(`/api/candidates/${id}`);
    state.selectedId = id;
    renderCandidateList();
    renderDetail();
  } catch (err) {
    toast(err.message, true);
  }
}

async function loadTimeline() {
  state.timeline = await api("/api/timeline");
  renderTimeline();
}

async function refreshAll() {
  await Promise.all([loadCandidates(state.selectedId), loadTimeline()]);
}

// ---------------------------------------------------------------------------
// Candidate queue
// ---------------------------------------------------------------------------

function renderCandidateList() {
  const host = $("#candidate-list");
  if (!state.candidates.length) {
    host.innerHTML = `<div class="empty-state" style="padding:34px 10px">该分类下暂无候选组</div>`;
    return;
  }
  host.innerHTML = state.candidates
    .map((c) => {
      const color = confColor(c.confidence.label);
      const sources = c.sources
        .map((s) => `<span class="src-dot"><span class="dot" style="background:${color}"></span>${esc(s.source_name || s.source_code)}</span>`)
        .join("");
      return `
      <div class="candidate-card ${c.id === state.selectedId ? "selected" : ""}" data-action="select" data-id="${c.id}">
        <div class="cc-top">
          <span class="cc-user">${esc(c.user_id || "未知用户")}</span>
          <span class="badge status-${c.status}">${statusText(c.status)}</span>
        </div>
        <div class="cc-meta">${esc(c.event_type)} · ${esc(c.id)}</div>
        <div class="cc-row">
          <span class="badge ${c.confidence.label}">${c.confidence.label_text} ${c.confidence.percent}%</span>
          <span class="conf-mini"><i style="width:${c.confidence.percent}%;background:${color}"></i></span>
        </div>
        <div class="cc-row" style="margin-top:8px">
          ${sources}
          <span class="src-dot">时间差 ${esc(c.time_delta_human)}</span>
          ${c.conflict_field_count ? `<span class="src-dot" style="color:var(--low)">${c.conflict_field_count} 项字段冲突</span>` : ""}
        </div>
      </div>`;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Detail workbench
// ---------------------------------------------------------------------------

function renderConfidence(conf) {
  const color = confColor(conf.label);
  const comps = conf.components
    .map(
      (c) => `
      <div class="comp">
        <div class="comp-label"><span>${esc(c.label)} · ${esc(c.detail)}</span><span>${c.score}/${c.max}</span></div>
        <div class="meter"><i style="width:${Math.round((c.score / c.max) * 100)}%;background:${color}"></i></div>
      </div>`
    )
    .join("");
  const findings = (conf.findings || [])
    .map(
      (f) =>
        `<span class="${f.status === "match" ? "chip-match" : "chip-conflict"}">${f.status === "match" ? "✓" : "≠"} ${esc(f.label)}</span>`
    )
    .join("");
  return `
    <div class="block">
      <h4>可信度分析</h4>
      <div class="conf-hero">
        <div class="conf-num" style="color:${color}">${conf.percent}<span style="font-size:16px">%</span></div>
        <div style="flex:1">
          <span class="badge ${conf.label}">${conf.label_text}</span>
          <div class="meter"><i style="width:${conf.percent}%;background:${color}"></i></div>
          <div class="comp-label"><span>可信度（按来源可靠度加权）</span><b>${Math.round(conf.trust_adjusted_score * 100)}%</b></div>
        </div>
      </div>
      ${comps}
      <div class="findings">${findings}</div>
    </div>`;
}

function renderTimes(detail) {
  const entries = detail.time_comparison.entries || [];
  const selectable = detail.status === "pending" || detail.status === "unknown";
  const topReliabilityId = entries.reduce(
    (best, e) => ((e.reliability || 0) > (best?.reliability || 0) ? e : best),
    null
  )?.record_id;
  const cards = entries
    .map((e) => {
      const relPct = Math.round((e.reliability || 0) * 100);
      return `
      <div class="time-card ${e.is_earliest ? "" : "latest"}">
        <div class="tc-head">
          <span class="tc-source">${esc(e.source_name || e.source_code)}</span>
          <span class="badge ${e.is_earliest ? "high" : "medium"}">${esc(e.offset_human)}</span>
        </div>
        <div class="tc-time">${esc(e.occurred_at)}</div>
        <div class="tc-raw">原始时间串：${esc(e.occurred_at_raw || "—")}</div>
        <div class="tc-rel">
          <span>来源可信度 ${relPct}%</span>
          <span class="rel-bar"><i style="width:${relPct}%"></i></span>
        </div>
        ${
          selectable
            ? `<label class="pick-time"><input type="radio" name="time-source" value="${e.record_id}" ${
                e.record_id === topReliabilityId ? "checked" : ""
              }/> 合并时采用此时间（默认最可信来源）</label>`
            : ""
        }
      </div>`;
    })
    .join("");
  return `
    <div class="block">
      <h4>各来源时间（相差 ${esc(detail.time_comparison.delta_human)}）</h4>
      ${cards}
    </div>`;
}

function renderDiff(detail) {
  const sources = detail.records;
  const head = `
    <tr>
      <th>字段</th>
      ${sources
        .map((r) => `<th>${esc(r.source_name || r.source_code)}</th>`)
        .join("")}
    </tr>`;
  const rows = detail.field_diff
    .map((f) => {
      const cells = f.values
        .map((v) => {
          if (!v.present) return `<td><span class="missing">未提供</span></td>`;
          const cls = f.conflict ? "val-conflict" : "val-same";
          return `<td class="${cls}">${esc(v.display)}</td>`;
        })
        .join("");
      return `
        <tr>
          <td class="field-name">${esc(f.label)}<span style="color:var(--muted);font-weight:400"> ${esc(f.field)}</span>${
            f.conflict ? '<span class="conflict-flag">冲突</span>' : ""
          }</td>
          ${cells}
        </tr>`;
    })
    .join("");
  return `
    <div class="block" style="margin-top:14px">
      <h4>字段差异对比</h4>
      <div style="overflow:auto;max-height:420px">
        <table class="diff"><thead>${head}</thead><tbody>${rows}</tbody></table>
      </div>
    </div>`;
}

function renderRawRecords(detail) {
  return detail.records
    .map((r) => {
      const json = esc(JSON.stringify(r.payload, null, 2));
      return `
      <details class="raw-record">
        <summary>
          <span>${esc(r.source_name || r.source_code)} · 原始记录 ${esc(r.id)}</span>
          <span style="color:var(--muted)">${esc(r.external_id)}</span>
        </summary>
        <pre>{
  "id": "${esc(r.id)}",
  "source_code": "${esc(r.source_code)}",
  "external_id": "${esc(r.external_id)}",
  "user_id": "${esc(r.user_id)}",
  "event_type": "${esc(r.event_type)}",
  "occurred_at": "${esc(r.occurred_at)}",
  "payload": ${json}
}</pre>
      </details>`;
    })
    .join("");
}

function actionButtons(detail) {
  const allowed = detail.allowed_actions || [];
  const btn = (action, cls, label) =>
    allowed.includes(action)
      ? `<button class="btn ${cls}" data-action="${action}" data-id="${detail.id}">${label}</button>`
      : "";
  return `
    <div class="actions">
      ${btn("keep", "btn-primary", "✓ 保留并合并为一个事件")}
      ${btn("split", "btn-split", "⇄ 拆分为独立事件")}
      ${btn("unknown", "btn-unknown", "? 标记未知")}
      ${btn("reopen", "btn-reopen", "↺ 重新处理")}
    </div>
    <input id="action-note" class="note-input" placeholder="处置备注（可选），将写入审计记录" />`;
}

function renderResolutionBanner(detail) {
  if (detail.status === "pending") return "";
  const note = detail.resolution_note ? `备注：${esc(detail.resolution_note)}` : "";
  let extra = "";
  if (detail.status === "merged" && detail.canonical_event_id) {
    extra = `<div>规范事件：<code>${esc(detail.canonical_event_id)}</code>（下方时间线可见，含全部 2 条原始记录）</div>`;
  }
  if (detail.status === "split" && detail.events) {
    extra = `<div>已生成 ${detail.events.length} 个独立时间线事件，每条原始记录各自保留。</div>`;
  }
  return `
    <div class="preserve-note" style="background:var(--brand-weak);color:var(--brand)">
      <strong>当前状态：${statusText(detail.status)}</strong>
      <div style="margin-top:4px">${extra}${note ? `<div>${note}</div>` : ""}</div>
    </div>`;
}

function renderDetail() {
  const host = $("#detail");
  const d = state.detail;
  if (!d) {
    host.innerHTML = `<div class="empty-state">${
      state.candidates.length ? "从左侧选择一个候选合并组进行审查" : "当前分类下没有候选组"
    }</div>`;
    return;
  }
  host.innerHTML = `
    <div class="detail-head">
      <div>
        <h3>${esc(d.user_id)} · ${esc(d.event_type)}</h3>
        <div class="sub">候选组 <code>${esc(d.id)}</code> · 来源记录 ${d.records.length} 条 · 创建于 ${esc(d.created_at)}</div>
      </div>
      <span class="badge status-${d.status}" style="font-size:13px;padding:5px 13px">${statusText(d.status)}</span>
    </div>
    ${renderResolutionBanner(d)}
    ${actionButtons(d)}
    <div class="grid-2">
      ${renderConfidence(d.confidence)}
      ${renderTimes(d)}
    </div>
    ${renderDiff(d)}
    <div class="block" style="margin-top:14px">
      <h4>各来源原始记录（合并 / 拆分均不会删除或改写）</h4>
      <div class="preserve-note">🔒 原始记录为只追加数据；任何处置后都可在此或时间线事件中查看完整原文。</div>
      ${renderRawRecords(d)}
    </div>`;
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

function renderTimeline() {
  const host = $("#timeline");
  $("#timeline-hint").textContent = state.timeline.length
    ? `共 ${state.timeline.length} 个规范事件`
    : "尚无规范事件 —— 请在上方审查候选组并选择保留或拆分";
  if (!state.timeline.length) {
    host.innerHTML = `<div class="empty-state" style="padding:30px">时间线为空</div>`;
    return;
  }
  host.innerHTML = state.timeline
    .map(
      (ev) => `
    <div class="tl-item">
      <div class="tl-rail"><div class="tl-dot"></div></div>
      <div class="tl-card">
        <div class="tl-title">
          ${esc(ev.title)}
          <span class="badge status-${ev.resolution === "merged" ? "merged" : "split"}">
            ${ev.resolution === "merged" ? "合并事件" : "拆分事件"}
          </span>
        </div>
        <div class="tl-time">规范时间 ${esc(ev.event_time)} · 关联 ${ev.record_count} 条原始记录 · 候选 <code>${esc(ev.candidate_id || "")}</code></div>
        <div class="tl-sources">
          ${ev.sources
            .map(
              (s) =>
                `<span class="tl-source">${esc(s.source_name || s.source_code)}：${esc(
                  s.source_time
                )} · 可信度 ${Math.round((s.reliability || 0) * 100)}%</span>`
            )
            .join("")}
        </div>
        <details class="tl-expand">
          <summary data-action="event-detail" data-id="${ev.id}">查看字段差异与全部原始记录（不会丢失）</summary>
          <div data-event-body="${ev.id}" style="margin-top:10px"><div class="loading">展开后加载…</div></div>
        </details>
      </div>
    </div>`
    )
    .join("");
}

async function loadTimelineEvent(id, bodyEl) {
  if (bodyEl.dataset.loaded === "1") return;
  try {
    const ev = await api(`/api/timeline/${id}`);
    bodyEl.dataset.loaded = "1";
    bodyEl.innerHTML =
      renderDiff({ records: ev.originals, field_diff: ev.field_diff }) +
      `<div class="block" style="margin-top:12px"><h4>原始记录</h4>${renderRawRecords({
        records: ev.originals,
      })}</div>`;
  } catch (err) {
    bodyEl.innerHTML = `<div style="color:var(--low)">${esc(err.message)}</div>`;
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function decide(id, action, trigger) {
  const note = ($("#action-note") && $("#action-note").value) || "";
  const body = { analyst: analystName(), note };
  if (action === "keep") {
    const picked = document.querySelector('input[name="time-source"]:checked');
    if (picked) body.time_source_record_id = picked.value;
  }
  if (trigger) trigger.disabled = true;
  try {
    await api(`/api/candidates/${id}/${action}`, { method: "POST", body });
    const label = { keep: "已保留并合并", split: "已拆分", unknown: "已标记未知", reopen: "已重新打开" }[action];
    toast(`${label}：${id}`);
    await refreshAll();
  } catch (err) {
    toast(err.message, true);
    if (trigger) trigger.disabled = false;
  }
}

document.addEventListener("click", async (event) => {
  const el = event.target.closest("[data-action]");
  if (!el) return;
  const { action, id } = el.dataset;
  if (action === "select") {
    await loadDetail(id);
  } else if (["keep", "split", "unknown", "reopen"].includes(action)) {
    await decide(id, action, el);
  } else if (action === "event-detail") {
    const bodyEl = document.querySelector(`[data-event-body="${id}"]`);
    if (bodyEl) await loadTimelineEvent(id, bodyEl);
  }
});

$("#status-tabs").addEventListener("click", (event) => {
  const tab = event.target.closest(".tab");
  if (!tab) return;
  document.querySelectorAll("#status-tabs .tab").forEach((t) => t.classList.remove("active"));
  tab.classList.add("active");
  state.status = tab.dataset.status;
  state.selectedId = null;
  state.detail = null;
  loadCandidates();
});

$("#detect").addEventListener("click", async () => {
  try {
    const result = await api("/api/candidates/detect?window_hours=24", { method: "POST" });
    toast(`检测完成，新增 ${result.created} 个候选组`);
    await loadCandidates();
  } catch (err) {
    toast(err.message, true);
  }
});

$("#reload-timeline").addEventListener("click", loadTimeline);

$("#reset-demo").addEventListener("click", async () => {
  if (!window.confirm("将清空当前处置结果并重建内置演示数据，确定吗？")) return;
  try {
    await api("/api/admin/reset-demo", { method: "POST" });
    state.selectedId = null;
    await refreshAll();
    toast("演示数据已重置");
  } catch (err) {
    toast(err.message, true);
  }
});

const savedAnalyst = localStorage.getItem("timeline-analyst");
if (savedAnalyst) $("#analyst").value = savedAnalyst;
$("#analyst").addEventListener("input", (e) =>
  localStorage.setItem("timeline-analyst", e.target.value)
);

refreshAll().catch((err) => toast(err.message, true));
