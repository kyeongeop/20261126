const state = { nodes: [], users: [], rootId: "", selected: null, view: null };

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function flash(text, ok = true) {
  const el = $("msg");
  el.textContent = text;
  el.className = ok ? "ok" : "err";
}

function nodeById(id) {
  return state.nodes.find((n) => n.id === id);
}

function childrenOf(parentId) {
  return state.nodes
    .filter((n) => n.parentId === parentId)
    .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === "folder" ? -1 : 1));
}

function renderTree() {
  const root = $("tree");
  root.innerHTML = "";
  const rootUl = document.createElement("ul");
  rootUl.className = "tree";
  rootUl.appendChild(treeNode(state.rootId));
  root.appendChild(rootUl);
}

function treeNode(id) {
  const node = nodeById(id);
  const li = document.createElement("li");
  const row = document.createElement("div");
  row.className = "node" + (state.selected === id ? " active" : "");
  row.innerHTML = `<span class="kind">${node.kind === "folder" ? "📁" : "📄"}</span><span>${node.name}</span>`;
  row.onclick = () => selectNode(id);
  li.appendChild(row);
  const kids = childrenOf(id);
  if (kids.length) {
    const ul = document.createElement("ul");
    kids.forEach((kid) => ul.appendChild(treeNode(kid.id)));
    li.appendChild(ul);
  }
  return li;
}

function renderMoveTargets() {
  const sel = $("moveTarget");
  sel.innerHTML = "";
  state.nodes
    .filter((n) => n.kind === "folder" && n.id !== state.selected)
    .forEach((n) => {
      const opt = document.createElement("option");
      opt.value = n.id;
      opt.textContent = n.path;
      sel.appendChild(opt);
    });
}

function renderUserSelects() {
  const sel = $("aceUser");
  sel.innerHTML = "";
  state.users.forEach((u) => {
    const opt = document.createElement("option");
    opt.value = u.id;
    opt.textContent = `${u.name}（${u.id}）`;
    sel.appendChild(opt);
  });
}

function levelText(level) {
  return { none: "none 显式拒绝", read: "read 只读", write: "write 可写", admin: "admin 管理" }[level] || level;
}

function sourceLabel(entry) {
  if (!entry.inherited) return `<span class="badge direct">本节点直接设置</span>`;
  const hops = state.view.chain.length - 1 - entry.depth;
  const where = entry.sourceNode === state.rootId ? "根目录" : `上级第 ${hops} 级`;
  return `<span class="badge inherited">继承 · ${where}</span>`;
}

async function selectNode(id) {
  state.selected = id;
  renderTree();
  renderMoveTargets();
  const view = await api(`/api/nodes/${id}/permissions`);
  state.view = view;
  $("nodeTitle").textContent = `权限编辑 · ${view.node.kind === "folder" ? "📁" : "📄"} ${view.node.path}`;
  $("chainBox").innerHTML =
    '<div class="muted">继承链（自根向下，越深优先级越高）：</div>' +
    '<div class="chain">' +
    view.chain.map((n, i) =>
      n.id === id ? `<span><b>${n.name}</b></span>` : `<span>${"└ ".repeat(i)}${n.name}</span>`
    ).join("") +
    "</div>";

  const body = $("permBody");
  body.innerHTML = "";
  if (!view.entries.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">暂无任何权限记录。</td></tr>';
  }
  view.entries.forEach((entry) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${entry.userName}<div class="src">${entry.userId}</div></td>
      <td class="${entry.level === "none" ? "lvl-none" : ""}">${levelText(entry.level)}</td>
      <td>${sourceLabel(entry)}</td>
      <td class="src">${entry.sourceName}<div>${entry.sourceNode} · 深度 ${entry.depth}</div></td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "danger";
    btn.textContent = entry.inherited ? "清除本节点覆盖" : "删除直接权限";
    btn.disabled = entry.inherited;
    btn.title = entry.inherited ? "该权限来自继承，本节点没有可删除的直接记录" : "删除后回退到继承";
    btn.onclick = async () => {
      await api(`/api/nodes/${id}/permissions/${entry.userId}`, { method: "DELETE" });
      await refresh();
      flash("已删除直接权限，当前权限回退到继承结果。");
    };
    tr.lastElementChild.appendChild(btn);
    body.appendChild(tr);
  });
}

async function refresh() {
  const [nodeData, userData] = await Promise.all([api("/api/nodes"), api("/api/users")]);
  state.nodes = nodeData.nodes;
  state.rootId = nodeData.rootId;
  state.users = userData.users;
  renderTree();
  renderUserSelects();
  if (state.selected && nodeById(state.selected)) {
    await selectNode(state.selected);
  } else {
    state.selected = state.rootId;
    renderTree();
  }
  renderMoveTargets();
}

$("createUserBtn").onclick = async () => {
  const name = $("newUserName").value.trim();
  if (!name) return flash("请输入成员姓名。", false);
  await api("/api/users", { method: "POST", body: JSON.stringify({ name }) });
  $("newUserName").value = "";
  await refresh();
  flash("成员已创建（同名成员以 ID 区分）。");
};

$("createNodeBtn").onclick = async () => {
  try {
    const node = await api("/api/nodes", {
      method: "POST",
      body: JSON.stringify({
        name: $("newNodeName").value.trim(),
        kind: $("newNodeKind").value,
        parentId: state.selected,
      }),
    });
    $("newNodeName").value = "";
    await refresh();
    await selectNode(node.id);
    flash("节点已创建，权限默认从父级继承。");
  } catch (err) {
    flash(err.message, false);
  }
};

$("setAceBtn").onclick = async () => {
  try {
    await api(`/api/nodes/${state.selected}/permissions/${$("aceUser").value}`, {
      method: "PUT",
      body: JSON.stringify({ level: $("aceLevel").value }),
    });
    await selectNode(state.selected);
    flash("单节点覆盖已保存（不影响其他目录与继承链）。");
  } catch (err) {
    flash(err.message, false);
  }
};

$("moveBtn").onclick = async () => {
  try {
    await api(`/api/nodes/${state.selected}/move`, {
      method: "POST",
      body: JSON.stringify({ newParentId: $("moveTarget").value }),
    });
    await refresh();
    flash("移动完成，子树有效权限已按新位置整体重算。");
  } catch (err) {
    flash(err.message, false);
  }
};

refresh().catch((err) => flash(err.message, false));
