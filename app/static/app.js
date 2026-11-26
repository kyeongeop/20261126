// Hypothesis cards UI. Switching hypotheses only re-renders the board;
// events themselves are never modified by judgment changes.

const state = { hypotheses: [], activeHypothesisId: null, board: null };

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!resp.ok) {
    const detail = await resp.text();
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.status === 204 ? null : resp.json();
}

async function loadHypotheses() {
  state.hypotheses = await api("/api/hypotheses");
  const list = document.getElementById("hypothesis-list");
  list.innerHTML = "";
  for (const h of state.hypotheses) {
    const li = document.createElement("li");
    li.textContent = h.title;
    li.dataset.id = h.id;
    if (h.id === state.activeHypothesisId) li.classList.add("active");
    li.addEventListener("click", () => selectHypothesis(h.id));
    list.appendChild(li);
  }
}

async function selectHypothesis(id) {
  // Only changes which projection is displayed; no event data is touched.
  state.activeHypothesisId = id;
  state.board = await api(`/api/hypotheses/${id}/board`);
  await loadHypotheses();
  renderBoard();
}

function renderBoard() {
  const board = state.board;
  document.getElementById("board").classList.remove("hidden");
  document.getElementById("board-title").textContent = board.hypothesis.title;
  document.getElementById("board-statement").textContent = board.hypothesis.statement;

  for (const verdict of ["support", "refute", "unknown"]) {
    const col = document.getElementById(`col-${verdict}`);
    col.innerHTML = "";
    document.getElementById(`count-${verdict}`).textContent = board[verdict].length;
    for (const judged of board[verdict]) {
      col.appendChild(buildCard(judged));
    }
  }
}

function buildCard(judged) {
  const tpl = document.getElementById("event-card-template");
  const card = tpl.content.firstElementChild.cloneNode(true);
  const event = judged.event;

  card.querySelector(".card-title").textContent = event.title;
  card.querySelector(".card-time").textContent = new Date(
    event.occurred_at
  ).toLocaleString();
  card.querySelector(".card-desc").textContent = event.description;
  card.querySelector(".card-source").textContent = event.source
    ? `来源：${event.source}`
    : "";

  const reasonInput = card.querySelector(".reason-input");
  reasonInput.value = judged.reason;

  let verdict = judged.verdict;
  const buttons = card.querySelectorAll(".verdict-buttons button");
  function markSelected() {
    buttons.forEach((b) =>
      b.classList.toggle("selected", b.dataset.verdict === verdict)
    );
  }
  markSelected();
  buttons.forEach((b) =>
    b.addEventListener("click", () => {
      verdict = b.dataset.verdict;
      markSelected();
    })
  );

  card.querySelector(".save-reason").addEventListener("click", async () => {
    await api(`/api/hypotheses/${state.activeHypothesisId}/events/${event.id}`, {
      method: "PUT",
      body: JSON.stringify({ verdict, reason: reasonInput.value }),
    });
    await selectHypothesis(state.activeHypothesisId);
  });

  return card;
}

document.getElementById("hypothesis-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const created = await api("/api/hypotheses", {
    method: "POST",
    body: JSON.stringify({
      title: document.getElementById("hypothesis-title").value,
      statement: document.getElementById("hypothesis-statement").value,
    }),
  });
  e.target.reset();
  await selectHypothesis(created.id);
});

document.getElementById("event-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await api("/api/events", {
    method: "POST",
    body: JSON.stringify({
      title: document.getElementById("event-title").value,
      occurred_at: new Date(
        document.getElementById("event-time").value
      ).toISOString(),
      source: document.getElementById("event-source").value,
      description: document.getElementById("event-description").value,
    }),
  });
  e.target.reset();
  if (state.activeHypothesisId) await selectHypothesis(state.activeHypothesisId);
});

loadHypotheses();
