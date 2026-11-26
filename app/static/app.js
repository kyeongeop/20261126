const state = {
  analysts: [],
  analystId: Number(localStorage.getItem("incident.analystId")) || null,
  cases: [],
  caseId: null,
  caseData: null,
  events: [],
  hypotheses: [],
  evidence: [],
  handovers: [],
};

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
      })[character],
  );

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
}

let toastTimer = null;
function toast(message, isError = false) {
  const element = byId("toast");
  element.textContent = message;
  element.classList.toggle("error", isError);
  element.classList.remove("hidden");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => element.classList.add("hidden"), 3200);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (state.analystId) headers["X-Analyst-Id"] = String(state.analystId);
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body:
      options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) {
    let detail = `请求失败 (${response.status})`;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch {
      // Keep the status-based fallback when the body is not JSON.
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

function currentAnalyst() {
  return state.analysts.find((analyst) => analyst.id === state.analystId) || null;
}

function bindNavigation() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
      button.classList.add("active");
      byId(`${button.dataset.tab}-tab`).classList.remove("hidden");
    });
  });

  byId("analyst-select").addEventListener("change", async (event) => {
    state.analystId = Number(event.target.value) || null;
    localStorage.setItem("incident.analystId", String(state.analystId || ""));
    await loadCases();
  });

  byId("add-analyst-button").addEventListener("click", addAnalyst);
  byId("new-case-button").addEventListener("click", addCase);
  byId("event-form").addEventListener("submit", addEvent);
  byId("hypothesis-form").addEventListener("submit", addHypothesis);
  byId("evidence-form").addEventListener("submit", addEvidence);
  byId("create-handover-button").addEventListener("click", createHandover);
}

async function addAnalyst() {
  const name = window.prompt("分析员姓名");
  if (!name || !name.trim()) return;
  try {
    const analyst = await api("/api/analysts", {
      method: "POST",
      body: { name: name.trim() },
    });
    state.analystId = analyst.id;
    localStorage.setItem("incident.analystId", String(analyst.id));
    await loadAnalysts();
    await loadCases();
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadAnalysts() {
  state.analysts = await api("/api/analysts");
  const select = byId("analyst-select");
  select.innerHTML = state.analysts
    .map(
      (analyst) =>
        `<option value="${analyst.id}">${escapeHtml(analyst.name)}</option>`,
    )
    .join("");
  if (!state.analysts.length) {
    state.analystId = null;
    select.innerHTML = '<option value="">暂无分析员</option>';
    return;
  }
  const stored = state.analysts.find((analyst) => analyst.id === state.analystId);
  state.analystId = stored ? stored.id : state.analysts[0].id;
  select.value = String(state.analystId);
  localStorage.setItem("incident.analystId", String(state.analystId));
}

async function addCase() {
  if (!state.analystId) {
    toast("请先新增并选择分析员", true);
    return;
  }
  const title = window.prompt("案件标题");
  if (!title || !title.trim()) return;
  try {
    const created = await api("/api/cases", {
      method: "POST",
      body: { title: title.trim() },
    });
    state.caseId = created.id;
    await loadCases();
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadCases() {
  const list = byId("case-list");
  if (!state.analystId) {
    state.cases = [];
    state.caseId = null;
    list.innerHTML = '<p class="empty">请先添加分析员。</p>';
    showWelcome();
    return;
  }
  try {
    state.cases = await api("/api/cases");
  } catch (error) {
    toast(error.message, true);
    return;
  }
  if (state.caseId && !state.cases.some((item) => item.id === state.caseId)) {
    state.caseId = null;
  }
  if (!state.cases.length) {
    list.innerHTML = '<p class="empty">当前分析员还没有案件。</p>';
    showWelcome();
    return;
  }
  if (!state.caseId) state.caseId = state.cases[0].id;
  renderCaseList();
  await loadCase();
}

function renderCaseList() {
  byId("case-list").innerHTML = state.cases
    .map(
      (item) => `
        <button class="case-item ${item.id === state.caseId ? "active" : ""}"
                data-case-id="${item.id}">
          <strong>${escapeHtml(item.title)}</strong>
          <span>${escapeHtml(item.owner_name)} · ${item.access_level === "owner" ? "可编辑" : "只读"}</span>
        </button>`,
    )
    .join("");
  document.querySelectorAll(".case-item").forEach((button) => {
    button.addEventListener("click", async () => {
      state.caseId = Number(button.dataset.caseId);
      renderCaseList();
      await loadCase();
    });
  });
}

function showWelcome() {
  byId("welcome").classList.remove("hidden");
  byId("case-workspace").classList.add("hidden");
}

async function loadCase() {
  if (!state.caseId) {
    showWelcome();
    return;
  }
  try {
    const [caseData, events, hypotheses, evidence, handovers] = await Promise.all([
      api(`/api/cases/${state.caseId}`),
      api(`/api/cases/${state.caseId}/events`),
      api(`/api/cases/${state.caseId}/hypotheses`),
      api(`/api/cases/${state.caseId}/evidence`),
      api(`/api/cases/${state.caseId}/handovers`),
    ]);
    state.caseData = caseData;
    state.events = events;
    state.hypotheses = hypotheses;
    state.evidence = evidence;
    state.handovers = handovers;
    const matchingCase = state.cases.find((item) => item.id === state.caseId);
    if (matchingCase) Object.assign(matchingCase, caseData);
    renderCaseHeader();
    renderTimeline();
    renderHandover();
    renderCaseList();
    byId("welcome").classList.add("hidden");
    byId("case-workspace").classList.remove("hidden");
  } catch (error) {
    toast(error.message, true);
  }
}

function renderCaseHeader() {
  const item = state.caseData;
  const owner = state.analysts.find((analyst) => analyst.id === item.owner_id);
  byId("case-eyebrow").textContent = `CASE #${item.id}`;
  byId("case-title").textContent = item.title;
  byId("case-meta").textContent =
    `负责人：${owner ? owner.name : item.owner_name}` +
    ` · 更新于 ${formatTime(item.updated_at)}`;
  const badge = byId("access-badge");
  badge.textContent = item.access_level === "owner" ? "可编辑" : "只读访问";
  badge.className = `badge ${item.access_level === "owner" ? "owner" : ""}`;

  const writable = item.access_level === "owner";
  ["event-form", "hypothesis-form", "evidence-form"].forEach((formId) => {
    byId(formId).querySelectorAll("input, textarea, select, button").forEach((field) => {
      field.disabled = !writable;
    });
  });
}

function canWrite() {
  return state.caseData?.access_level === "owner";
}

async function addEvent(event) {
  event.preventDefault();
  if (!canWrite()) {
    toast("当前为只读访问，不能新增事件", true);
    return;
  }
  const form = event.currentTarget;
  const data = new FormData(form);
  try {
    await api(`/api/cases/${state.caseId}/events`, {
      method: "POST",
      body: {
        title: data.get("title"),
        description: data.get("description"),
        occurred_at: data.get("occurred_at"),
      },
    });
    form.reset();
    toast("事件已加入时间线");
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

async function addHypothesis(event) {
  event.preventDefault();
  if (!canWrite()) {
    toast("当前为只读访问，不能新增假设", true);
    return;
  }
  const form = event.currentTarget;
  const data = new FormData(form);
  try {
    await api(`/api/cases/${state.caseId}/hypotheses`, {
      method: "POST",
      body: {
        statement: data.get("statement"),
        status: data.get("status"),
      },
    });
    form.reset();
    toast("假设已记录");
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

async function addEvidence(event) {
  event.preventDefault();
  if (!canWrite()) {
    toast("当前为只读访问，不能登记证据", true);
    return;
  }
  const form = event.currentTarget;
  const data = new FormData(form);
  try {
    await api(`/api/cases/${state.caseId}/evidence`, {
      method: "POST",
      body: {
        title: data.get("title"),
        description: data.get("description"),
        status: data.get("status"),
      },
    });
    form.reset();
    toast("证据项已登记");
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderTimeline() {
  byId("event-count").textContent = state.events.length;
  byId("hypothesis-count").textContent = state.hypotheses.length;
  byId("evidence-count").textContent = state.evidence.length;

  byId("event-list").innerHTML =
    state.events
      .map(
        (item) => `
          <article class="record">
            <div class="record-title">
              <span>${escapeHtml(item.title)}</span>
              <span class="status-dot ${item.is_confirmed ? "done" : ""}">
                ${item.is_confirmed ? "已确认" : "未确认"}
              </span>
            </div>
            <p>${escapeHtml(formatTime(item.occurred_at))}${item.description ? `\n${escapeHtml(item.description)}` : ""}</p>
            ${
              canWrite() && !item.is_confirmed
                ? `<div class="record-actions"><button class="small" data-confirm-event="${item.id}">确认事件</button></div>`
                : ""
            }
          </article>`,
      )
      .join("") || '<p class="empty">暂无事件。</p>';

  byId("hypothesis-list").innerHTML =
    state.hypotheses
      .map((item) => {
        const finished = ["resolved", "rejected", "confirmed", "closed"].includes(
          item.status.toLowerCase(),
        );
        return `
          <article class="record">
            <div class="record-title">
              <span>${escapeHtml(item.statement)}</span>
              <span class="status-dot ${finished ? "done" : ""}">${escapeHtml(item.status)}</span>
            </div>
            ${
              canWrite() && !finished
                ? `<div class="record-actions"><button class="small" data-resolve-hypothesis="${item.id}">标记已解决</button></div>`
                : ""
            }
          </article>`;
      })
      .join("") || '<p class="empty">暂无假设。</p>';

  byId("evidence-list").innerHTML =
    state.evidence
      .map((item) => {
        const done = ["verified", "collected", "completed", "received"].includes(
          item.status.toLowerCase(),
        );
        return `
          <article class="record">
            <div class="record-title">
              <span>${escapeHtml(item.title)}</span>
              <span class="status-dot ${done ? "done" : ""}">${escapeHtml(item.status)}</span>
            </div>
            ${item.description ? `<p>${escapeHtml(item.description)}</p>` : ""}
            ${
              canWrite() && !done
                ? `<div class="record-actions"><button class="small" data-verify-evidence="${item.id}">标记已核验</button></div>`
                : ""
            }
          </article>`;
      })
      .join("") || '<p class="empty">暂无证据项。</p>';

  document.querySelectorAll("[data-confirm-event]").forEach((button) => {
    button.addEventListener("click", () =>
      patchTimeline(
        "events",
        button.dataset.confirmEvent,
        { is_confirmed: true },
      ),
    );
  });
  document.querySelectorAll("[data-resolve-hypothesis]").forEach((button) => {
    button.addEventListener("click", () =>
      patchTimeline("hypotheses", button.dataset.resolveHypothesis, {
        status: "resolved",
      }),
    );
  });
  document.querySelectorAll("[data-verify-evidence]").forEach((button) => {
    button.addEventListener("click", () =>
      patchTimeline("evidence", button.dataset.verifyEvidence, {
        status: "verified",
      }),
    );
  });
}

async function patchTimeline(resource, id, body) {
  try {
    await api(`/api/cases/${state.caseId}/${resource}/${id}`, {
      method: "PATCH",
      body,
    });
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

const checklistGroups = [
  ["unconfirmed_events", "未确认事件"],
  ["unfinished_hypotheses", "未完成假设"],
  ["evidence_to_supplement", "待补证据"],
  ["permission", "权限说明"],
];

function renderHandover() {
  const successorSelect = byId("successor-select");
  const candidates = state.analysts.filter(
    (analyst) => analyst.id !== state.analystId,
  );
  const previousSelection = successorSelect.value;
  successorSelect.innerHTML = candidates
    .map(
      (analyst) =>
        `<option value="${analyst.id}">${escapeHtml(analyst.name)}</option>`,
    )
    .join("");
  if (
    previousSelection &&
    candidates.some((analyst) => String(analyst.id) === previousSelection)
  ) {
    successorSelect.value = previousSelection;
  }
  byId("create-handover-button").disabled =
    !canWrite() || candidates.length === 0;

  const content = byId("handover-content");
  const handover = state.handovers[0];
  if (!handover) {
    content.innerHTML = `
      <div class="card">
        <p class="empty">暂无交接记录。选择接手人并点击“发起交接”后，系统会自动生成清单。</p>
      </div>`;
    return;
  }

  const isFrom = handover.from_analyst.id === state.analystId;
  const isTo = handover.to_analyst.id === state.analystId;
  const pending = handover.status === "pending";
  const checklistEditable =
    (pending && (isFrom || isTo)) ||
    (!pending && handover.status === "confirmed" && isTo && canWrite());
  const canConfirm = pending && isTo;
  const statusLabel =
    handover.status === "pending"
      ? "待接手人确认"
      : handover.status === "confirmed"
        ? "已确认 · 权限已切换"
        : "已取消";

  const groups = checklistGroups
    .map(([key, label]) => {
      const items = handover.checklist[key] || [];
      return `
        <div class="checklist-group">
          <div class="checklist-heading">
            <h4>${label}</h4>
            <span>${items.length} 项</span>
          </div>
          ${
            items.length
              ? items
                  .map((item) =>
                    renderChecklistItem(
                      item,
                      checklistEditable,
                      isFrom && pending,
                      isTo,
                    ),
                  )
                  .join("")
              : '<p class="empty checklist-item">本类暂无待处理项。</p>'
          }
        </div>`;
    })
    .join("");

  content.innerHTML = `
    <article class="card handover-card">
      <div class="handover-summary">
        <div class="section-title">
          <h3>${escapeHtml(handover.from_analyst.name)} → ${escapeHtml(handover.to_analyst.name)}</h3>
          <span class="badge ${handover.status === "confirmed" ? "owner" : ""}">${statusLabel}</span>
        </div>
        <p>${escapeHtml(handover.permission_summary)}</p>
        <p class="muted">发起于 ${formatTime(handover.created_at)}${handover.confirmed_at ? ` · 确认于 ${formatTime(handover.confirmed_at)}` : ""}</p>
      </div>
      ${groups}
      <div class="handover-footer">
        ${
          checklistEditable
            ? '<button id="refresh-handover-button" class="secondary">按最新状态刷新清单</button>'
            : ""
        }
        ${
          canConfirm
            ? '<button id="confirm-handover-button">确认交接并成为负责人</button>'
            : ""
        }
      </div>
    </article>`;

  if (checklistEditable) {
    byId("refresh-handover-button")?.addEventListener("click", refreshHandover);
  }
  if (canConfirm) {
    byId("confirm-handover-button")?.addEventListener("click", confirmHandover);
  }
  bindChecklistActions(handover);
}

function renderChecklistItem(item, editable, canAddOutgoing, canAddSuccessor) {
  const outgoingButton =
    editable && canAddOutgoing
      ? `<button class="small secondary" data-append-note="outgoing" data-item-id="${item.id}">追加旧负责人备注</button>`
      : "";
  const successorButton =
    editable && canAddSuccessor
      ? `<button class="small secondary" data-append-note="successor" data-item-id="${item.id}">追加接手人备注</button>`
      : "";
  return `
    <div class="checklist-item">
      <div class="checklist-item-main">
        <input type="checkbox" data-check-item="${item.id}"
               ${item.checked ? "checked" : ""} ${editable ? "" : "disabled"}
               aria-label="核对 ${escapeHtml(item.title)}" />
        <div>
          <strong>${escapeHtml(item.title)}</strong>
          <p class="checklist-detail">${escapeHtml(item.detail)}</p>
          <p class="muted">${item.checked ? "已核对" : "未核对"}${item.source_status ? ` · ${escapeHtml(item.source_status)}` : ""}</p>
        </div>
      </div>
      <div class="notes">
        <div class="note-block">
          <label>旧负责人手写备注（只追加）</label>
          <p>${escapeHtml(item.outgoing_note) || "暂无备注"}</p>
          ${
            editable && canAddOutgoing
              ? `<textarea id="outgoing-note-${item.id}" placeholder="补充检查情况、线索位置或注意事项"></textarea>${outgoingButton}`
              : ""
          }
        </div>
        <div class="note-block">
          <label>接手人备注</label>
          <p>${escapeHtml(item.successor_note) || "暂无备注"}</p>
          ${
            editable && canAddSuccessor
              ? `<textarea id="successor-note-${item.id}" placeholder="记录接手核对结果"></textarea>${successorButton}`
              : ""
          }
        </div>
      </div>
    </div>`;
}

function bindChecklistActions(handover) {
  document.querySelectorAll("[data-check-item]").forEach((checkbox) => {
    checkbox.addEventListener("change", () =>
      patchChecklistItem(handover.id, Number(checkbox.dataset.checkItem), {
        checked: checkbox.checked,
      }),
    );
  });
  document.querySelectorAll("[data-append-note]").forEach((button) => {
    button.addEventListener("click", () => {
      const itemId = Number(button.dataset.itemId);
      const noteKind = button.dataset.appendNote;
      const field = byId(
        `${noteKind === "outgoing" ? "outgoing" : "successor"}-note-${itemId}`,
      );
      if (!field || !field.value.trim()) {
        toast("请先填写要追加的备注", true);
        return;
      }
      patchChecklistItem(handover.id, itemId, {
        [noteKind === "outgoing" ? "outgoing_note" : "successor_note"]:
          field.value,
      });
    });
  });
}

async function patchChecklistItem(handoverId, itemId, body) {
  try {
    await api(
      `/api/cases/${state.caseId}/handovers/${handoverId}/items/${itemId}`,
      { method: "PATCH", body },
    );
    await loadCase();
  } catch (error) {
    toast(error.message, true);
    await loadCase();
  }
}

async function createHandover() {
  const successorId = Number(byId("successor-select").value);
  if (!successorId) {
    toast("请选择接手人", true);
    return;
  }
  try {
    await api(`/api/cases/${state.caseId}/handovers`, {
      method: "POST",
      body: { to_analyst_id: successorId },
    });
    toast("交接清单已生成，请核对后确认");
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

async function refreshHandover() {
  const handover = state.handovers[0];
  if (!handover) return;
  try {
    await api(
      `/api/cases/${state.caseId}/handovers/${handover.id}/refresh`,
      { method: "POST" },
    );
    toast("清单已按最新案件状态刷新，原有备注已保留");
    await loadCase();
  } catch (error) {
    toast(error.message, true);
  }
}

async function confirmHandover() {
  const handover = state.handovers[0];
  if (!handover) return;
  if (!window.confirm("确认接收案件？确认后旧负责人将只能查看，不能再编辑。")) {
    return;
  }
  try {
    await api(
      `/api/cases/${state.caseId}/handovers/${handover.id}/confirm`,
      { method: "POST" },
    );
    toast("交接已确认，你现在是案件负责人");
    await loadCases();
  } catch (error) {
    toast(error.message, true);
  }
}

async function init() {
  bindNavigation();
  try {
    await loadAnalysts();
    await loadCases();
  } catch (error) {
    toast(error.message, true);
  }
}

init();
