const state = {
  preset: "all",
  from: "",
  to: "",
  usage: "all",
  query: "",
  data: null,
  requestID: 0,
};

const elements = {
  body: document.getElementById("cert-table-body"),
  empty: document.getElementById("empty-state"),
  count: document.getElementById("result-count"),
  scanTime: document.getElementById("scan-time"),
  gatewayMeta: document.getElementById("gateway-meta"),
  search: document.getElementById("search-input"),
  expiry: document.getElementById("expiry-select"),
  usage: document.getElementById("usage-select"),
  dateFilter: document.getElementById("date-filter"),
  dateFrom: document.getElementById("date-from"),
  dateTo: document.getElementById("date-to"),
  applyDates: document.getElementById("apply-dates"),
  reset: document.getElementById("reset-button"),
  emptyReset: document.getElementById("empty-reset"),
  reload: document.getElementById("reload-button"),
  attention: document.getElementById("attention"),
  attentionTitle: document.getElementById("attention-title"),
  attentionDetail: document.getElementById("attention-detail"),
  attentionAction: document.getElementById("attention-action"),
  toast: document.getElementById("toast"),
  backdrop: document.getElementById("drawer-backdrop"),
  drawer: document.getElementById("detail-drawer"),
  drawerTitle: document.getElementById("drawer-title"),
  drawerBody: document.getElementById("drawer-body"),
  drawerClose: document.getElementById("drawer-close"),
  statTotal: document.getElementById("stat-total"),
  statActive: document.getElementById("stat-active"),
  statExpiring: document.getElementById("stat-expiring"),
  statExpired: document.getElementById("stat-expired"),
  statStale: document.getElementById("stat-stale"),
  statTotalHint: document.getElementById("stat-total-hint"),
  statExpiringHint: document.getElementById("stat-expiring-hint"),
};

const icons = {
  lock: `<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="4.5" y="8.5" width="11" height="8" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M7 8.5V6.7a3 3 0 1 1 6 0v1.8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><path d="M10 11.5v2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`,
  arrow: `<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m7.5 5 5 5-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  shield: `<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 2.8 16 5v4.4c0 3.5-2.4 6.7-6 7.8-3.6-1.1-6-4.3-6-7.8V5l6-2.2Z" stroke="currentColor" stroke-width="1.5"/><path d="m7.5 9.9 1.7 1.7 3.4-3.7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
};

const chainBadges = {
  complete: { className: "green", label: "完整" },
  missing_intermediate: { className: "amber", label: "缺少中间证书" },
  untrusted: { className: "red", label: "链不受信任" },
  invalid: { className: "red", label: "无法读取" },
};

const usageBadges = {
  active: { className: "green", label: "使用中" },
  stale: { className: "violet", label: "文件不一致" },
  standby: { className: "slate", label: "未启用" },
  pending: { className: "blue", label: "待重载" },
  unloaded: { className: "red", label: "未加载" },
};

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function shortFingerprint(value) {
  if (!value) return "—";
  const normalized = value.toUpperCase();
  return `${normalized.slice(0, 8)} ${normalized.slice(8, 16)} … ${normalized.slice(-8)}`;
}

function expiryText(cert) {
  if (cert.expired) {
    const days = Math.abs(cert.days_remaining);
    return days === 0 ? "今天已过期" : `已过期 ${days} 天`;
  }
  if (cert.days_remaining <= 0) return "今天到期";
  return `剩余 ${cert.days_remaining} 天`;
}

function expiryClass(cert) {
  if (cert.expired || cert.days_remaining <= 7) return "is-danger";
  if (cert.days_remaining <= 30) return "is-warn";
  return "";
}

function buildQuery() {
  const params = new URLSearchParams();
  if (state.preset && state.preset !== "all") params.set("expiry", state.preset);
  if (state.preset === "custom") {
    if (state.from) params.set("expires_after", state.from);
    if (state.to) params.set("expires_before", state.to);
  }
  if (state.usage && state.usage !== "all") params.set("usage", state.usage);
  if (state.query.trim()) params.set("q", state.query.trim());
  return params.toString();
}

async function loadInventory({ quiet = false } = {}) {
  const requestID = ++state.requestID;
  if (!quiet) {
    elements.body.innerHTML = `<tr class="loading-row"><td colspan="6"><span class="loading-dot"></span>正在扫描证书库存…</td></tr>`;
    elements.empty.hidden = true;
  }

  try {
    const query = buildQuery();
    const response = await fetch(`/api/certificates${query ? `?${query}` : ""}`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "读取证书库存失败");
    if (requestID !== state.requestID) return;
    state.data = payload;
    render(payload);
  } catch (error) {
    if (requestID !== state.requestID) return;
    elements.body.innerHTML = `<tr class="loading-row"><td colspan="6">读取失败：${escapeHTML(error.message)}</td></tr>`;
    notify(`读取失败：${error.message}`, true);
  }
}

function render(data) {
  renderSummary(data);
  renderAttention(data);
  renderTable(data);
  elements.scanTime.textContent = formatDateTime(data.generated_at);
  elements.gatewayMeta.textContent = data.gateway?.reloaded_at
    ? `网关快照 ${formatDateTime(data.gateway.reloaded_at)}`
    : "网关快照尚未建立";
  elements.count.textContent = `显示 ${data.visible} / ${data.summary.total} 张`;
  elements.statTotalHint.textContent = `${data.summary.incomplete} 张链待修复`;
  elements.statExpiringHint.textContent = `${data.summary.expiring_7} 张在 7 天内到期`;
}

function renderSummary(data) {
  const summary = data.summary;
  elements.statTotal.textContent = summary.total;
  elements.statActive.textContent = summary.active;
  elements.statExpiring.textContent = summary.expiring_30;
  elements.statExpired.textContent = summary.expired;
  elements.statStale.textContent = summary.inconsistent;
}

function renderAttention(data) {
  const summary = data.summary;
  const issues = [];
  if (summary.inconsistent > 0) issues.push(`${summary.inconsistent} 张证书文件已替换但网关未重载（不一致）`);
  if (summary.expired > 0) issues.push(`${summary.expired} 张证书已过期`);
  if (summary.expiring_30 > 0) issues.push(`${summary.expiring_30} 张将在 30 天内到期`);
  if (summary.incomplete > 0) issues.push(`${summary.incomplete} 张证书链不完整`);

  if (issues.length === 0) {
    elements.attention.hidden = true;
    return;
  }

  elements.attention.hidden = false;
  elements.attention.classList.toggle("is-critical", summary.expired > 0 || summary.inconsistent > 0);
  elements.attentionTitle.textContent = summary.expired > 0
    ? `${summary.expired + summary.inconsistent} 项需要立即处理`
    : `${issues.length} 类证书风险需要关注`;
  elements.attentionDetail.textContent = issues.join(" · ");
  const target = summary.inconsistent > 0 ? "stale" : summary.expired > 0 ? "expired" : "all";
  elements.attentionAction.textContent = target === "stale"
    ? "查看未重载证书"
    : target === "expired" ? "查看已过期证书" : "查看全部证书";
  elements.attentionAction.dataset.target = target;
}

function renderTable(data) {
  if (!data.certificates.length) {
    elements.body.innerHTML = "";
    elements.empty.hidden = false;
    return;
  }

  elements.empty.hidden = true;
  elements.body.innerHTML = data.certificates.map((cert) => {
    const chain = chainBadges[cert.chain?.status] || chainBadges.invalid;
    const usage = usageBadges[cert.usage?.state] || usageBadges.unloaded;
    const rowClasses = [
      cert.expired ? "is-expired" : "",
      cert.usage?.state === "stale" ? "is-stale" : "",
    ].filter(Boolean).join(" ");
    const extraDomains = cert.dns_names.length > 1
      ? `<span class="mini-tag">+${cert.dns_names.length - 1} SAN</span>`
      : "";

    return `
      <tr class="${rowClasses}">
        <td>
          <div class="domain-cell">
            <span class="domain-icon">${icons.lock}</span>
            <div class="domain-cell__copy">
              <span class="domain-name" title="${escapeHTML(cert.domain)}">${escapeHTML(cert.domain)}${extraDomains}</span>
              <span class="domain-path" title="${escapeHTML(cert.cert_path)}">${escapeHTML(cert.cert_path)}</span>
            </div>
          </div>
        </td>
        <td>
          <div class="issuer-cell">
            <span title="${escapeHTML(cert.issuer)}">${escapeHTML(cert.issuer)}</span>
            <small>${escapeHTML((cert.fingerprint || "").slice(0, 12).toUpperCase())}</small>
          </div>
        </td>
        <td>
          <div class="expiry-cell">
            <span class="expiry-date">${formatDate(cert.expires_at)}</span>
            <span class="expiry-relative ${expiryClass(cert)}">${expiryText(cert)}</span>
          </div>
        </td>
        <td>
          <div class="status-cell">
            <span class="badge badge--${chain.className}">${chain.label}</span>
            <span class="chain-detail" title="${escapeHTML(cert.chain?.detail)}">${escapeHTML(cert.chain?.detail)}</span>
          </div>
        </td>
        <td>
          <div class="status-cell">
            <span class="badge badge--${usage.className}">${usage.label}</span>
            <span class="status-detail" title="${escapeHTML(cert.usage?.detail)}">${escapeHTML(cert.usage?.detail)}</span>
          </div>
        </td>
        <td>
          <button class="row-action" type="button" data-cert-id="${escapeHTML(cert.id)}" aria-label="查看 ${escapeHTML(cert.domain)} 详情">
            ${icons.arrow}
          </button>
        </td>
      </tr>`;
  }).join("");
}

function openDetails(certID) {
  const cert = state.data?.certificates.find((item) => item.id === certID);
  if (!cert) return;

  const chain = chainBadges[cert.chain?.status] || chainBadges.invalid;
  const usage = usageBadges[cert.usage?.state] || usageBadges.unloaded;
  elements.drawerTitle.textContent = cert.domain;
  elements.drawerBody.innerHTML = `
    <div class="detail-hero">
      <span class="detail-hero__icon">${icons.shield}</span>
      <div>
        <h3>${escapeHTML(cert.domain)}</h3>
        <p>由 ${escapeHTML(cert.issuer)} 签发 · ${formatDate(cert.expires_at)} 到期</p>
      </div>
    </div>
    <div class="detail-badges">
      <span class="badge badge--${usage.className}">${usage.label}</span>
      <span class="badge badge--${chain.className}">链 · ${chain.label}</span>
      <span class="badge badge--${cert.expired ? "red" : expiryClass(cert) ? "amber" : "slate"}">${expiryText(cert)}</span>
    </div>
    ${cert.usage?.state === "stale" ? `
      <div class="detail-note ${cert.expired ? "is-critical" : ""}">
        网关内存中仍是上一次重载的证书，与磁盘文件不一致。确认新证书无误后，点击右上角“重载网关”使其生效。
      </div>` : ""}
    <section class="detail-section">
      <h4>证书信息</h4>
      <dl class="detail-list">
        <div class="detail-row"><dt>域名</dt><dd>${escapeHTML(cert.domain)}</dd></div>
        <div class="detail-row"><dt>SAN</dt><dd>${escapeHTML(cert.dns_names.join(", "))}</dd></div>
        <div class="detail-row"><dt>签发者</dt><dd>${escapeHTML(cert.issuer)}</dd></div>
        <div class="detail-row"><dt>有效期</dt><dd>${formatDate(cert.not_before)} — ${formatDate(cert.expires_at)}</dd></div>
        <div class="detail-row"><dt>序列号</dt><dd class="mono">${escapeHTML(cert.serial_number)}</dd></div>
        <div class="detail-row"><dt>链完整性</dt><dd>${escapeHTML(cert.chain?.detail)}</dd></div>
      </dl>
    </section>
    <section class="detail-section">
      <h4>网关使用状态</h4>
      <dl class="detail-list">
        <div class="detail-row"><dt>当前状态</dt><dd>${escapeHTML(cert.usage?.detail)}</dd></div>
        <div class="detail-row"><dt>快照重载</dt><dd>${formatDateTime(cert.usage?.loaded_at)}</dd></div>
        <div class="detail-row"><dt>内存版本到期</dt><dd>${formatDate(cert.usage?.loaded_expires_at)}</dd></div>
        <div class="detail-row"><dt>磁盘指纹</dt><dd class="mono">${escapeHTML(shortFingerprint(cert.fingerprint))}</dd></div>
        <div class="detail-row"><dt>网关指纹</dt><dd class="mono">${escapeHTML(shortFingerprint(cert.usage?.loaded_fingerprint))}</dd></div>
      </dl>
    </section>
    <section class="detail-section">
      <h4>文件位置</h4>
      <dl class="detail-list">
        <div class="detail-row"><dt>证书文件</dt><dd class="mono">${escapeHTML(cert.cert_path)}</dd></div>
        <div class="detail-row"><dt>私钥文件</dt><dd class="mono">${escapeHTML(cert.key_path)}</dd></div>
        <div class="detail-row"><dt>文件修改时间</dt><dd>${formatDateTime(cert.file_modified_at)}</dd></div>
      </dl>
    </section>
    ${cert.error ? `<div class="detail-note is-critical">${escapeHTML(cert.error)}</div>` : ""}
  `;

  elements.backdrop.hidden = false;
  elements.drawer.classList.add("is-open");
  elements.drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
  elements.drawerClose.focus();
}

function closeDetails() {
  elements.drawer.classList.remove("is-open");
  elements.drawer.setAttribute("aria-hidden", "true");
  document.body.classList.remove("drawer-open");
  window.setTimeout(() => {
    elements.backdrop.hidden = true;
  }, 220);
}

let toastTimer = null;
function notify(message, isError = false) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("is-error", isError);
  elements.toast.hidden = false;
  toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 4200);
}

function syncFilterControls() {
  elements.expiry.value = state.preset;
  elements.usage.value = state.usage;
  elements.dateFilter.hidden = state.preset !== "custom";
  elements.dateFrom.value = state.from;
  elements.dateTo.value = state.to;
}

function resetFilters() {
  state.preset = "all";
  state.from = "";
  state.to = "";
  state.usage = "all";
  state.query = "";
  elements.search.value = "";
  syncFilterControls();
  loadInventory();
}

let searchTimer = null;
elements.search.addEventListener("input", (event) => {
  state.query = event.target.value;
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => loadInventory({ quiet: true }), 220);
});

elements.expiry.addEventListener("change", (event) => {
  state.preset = event.target.value;
  elements.dateFilter.hidden = state.preset !== "custom";
  if (state.preset === "custom") {
    elements.dateFrom.focus();
    return;
  }
  loadInventory();
});

elements.usage.addEventListener("change", (event) => {
  state.usage = event.target.value;
  loadInventory();
});

elements.applyDates.addEventListener("click", () => {
  state.preset = "custom";
  state.from = elements.dateFrom.value;
  state.to = elements.dateTo.value;
  if (state.from && state.to && state.from > state.to) {
    notify("开始日期不能晚于结束日期。", true);
    return;
  }
  loadInventory();
});

elements.dateFrom.addEventListener("change", () => {
  state.from = elements.dateFrom.value;
});

elements.dateTo.addEventListener("change", () => {
  state.to = elements.dateTo.value;
});

elements.reset.addEventListener("click", resetFilters);
elements.emptyReset.addEventListener("click", resetFilters);

elements.body.addEventListener("click", (event) => {
  const button = event.target.closest("[data-cert-id]");
  if (button) openDetails(button.dataset.certId);
});

elements.drawerClose.addEventListener("click", closeDetails);
elements.backdrop.addEventListener("click", closeDetails);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && elements.drawer.classList.contains("is-open")) closeDetails();
});

elements.attentionAction.addEventListener("click", () => {
  const target = elements.attentionAction.dataset.target;
  if (target === "stale") {
    state.usage = "stale";
    state.preset = "all";
  } else if (target === "expired") {
    state.usage = "all";
    state.preset = "expired";
  } else {
    state.usage = "all";
    state.preset = "all";
  }
  syncFilterControls();
  loadInventory();
  document.querySelector(".inventory-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
});

elements.reload.addEventListener("click", async () => {
  elements.reload.disabled = true;
  const original = elements.reload.innerHTML;
  elements.reload.innerHTML = `<span class="loading-dot"></span>重载中…`;
  try {
    const response = await fetch("/api/gateway/reload", {
      method: "POST",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "网关重载失败");
    }
    if (payload.status === "partial") {
      throw new Error(payload.error || "部分证书未能加载");
    }
    notify("网关已重载，证书内存快照已更新。");
  } catch (error) {
    notify(`重载未完成：${error.message}`, true);
  } finally {
    elements.reload.disabled = false;
    elements.reload.innerHTML = original;
    await loadInventory({ quiet: true });
  }
});

syncFilterControls();
loadInventory();
window.setInterval(() => {
  if (!document.hidden) loadInventory({ quiet: true });
}, 30000);
