let examples = { baseline: "", candidate: "", policy: "" };
let lastResult = null;

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

function setMode(mode) {
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.mode === mode));
  document.querySelectorAll(".mode-panel").forEach((panel) => panel.classList.toggle("active", panel.id === mode));
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

function candidateForToggle(enabled) {
  if (enabled) return examples.candidate;
  return examples.baseline.replace("acme-procurement-baseline", "acme-procurement-no-change");
}

function decisionClass(decision) {
  const value = String(decision || "neutral").toLowerCase();
  return ["block", "review", "pass", "allow", "neutral"].includes(value) ? value : "neutral";
}

function plainToken(token) {
  return String(token).replace(/^agent:/, "").replace(/^tool:/, "").replace(/^cap:/, "");
}

function pathNodeIds(path) {
  const ids = [];
  for (const token of path || []) {
    if (token.startsWith("delegate:")) continue;
    if (token.startsWith("tool:")) ids.push(token);
    else if (token.startsWith("cap:")) ids.push(token);
    else ids.push(`agent:${token}`);
  }
  return ids;
}

function layoutGraph(graph) {
  const groups = {
    agent: graph.nodes.filter((n) => n.type === "agent"),
    tool: graph.nodes.filter((n) => n.type === "tool"),
    capability: graph.nodes.filter((n) => n.type === "capability"),
  };
  const x = { agent: 45, tool: 295, capability: 545 };
  const positions = {};
  Object.entries(groups).forEach(([type, nodes]) => {
    nodes.forEach((node, index) => {
      positions[node.id] = { x: x[type], y: 46 + index * 92 };
    });
  });
  return { positions, height: Math.max(360, 110 + Math.max(groups.agent.length, groups.tool.length, groups.capability.length) * 92) };
}

function renderGraph(result) {
  const canvas = $("graphCanvas");
  const empty = $("graphEmpty");
  empty.hidden = true;
  canvas.hidden = false;
  canvas.innerHTML = "";
  const hotPath = pathNodeIds(result.primary_path || []);
  const { positions, height } = layoutGraph(result.graph);
  canvas.style.height = `${height}px`;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "graph-svg");
  svg.setAttribute("width", "760");
  svg.setAttribute("height", String(height));

  for (const edge of result.graph.edges) {
    const from = positions[edge.from];
    const to = positions[edge.to];
    if (!from || !to) continue;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", from.x + 170);
    line.setAttribute("y1", from.y + 28);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y + 28);
    const fromIdx = hotPath.indexOf(edge.from);
    const hot = fromIdx >= 0 && hotPath[fromIdx + 1] === edge.to;
    line.setAttribute("class", `graph-line${hot ? " hot" : ""}`);
    svg.appendChild(line);
  }
  canvas.appendChild(svg);

  for (const node of result.graph.nodes) {
    const pos = positions[node.id];
    if (!pos) continue;
    const el = document.createElement("div");
    const hot = hotPath.includes(node.id);
    el.className = `graph-node ${node.type}${hot ? " hot" : ""}`;
    el.style.left = `${pos.x}px`;
    el.style.top = `${pos.y}px`;
    el.innerHTML = `<strong>${esc(plainToken(node.label))}</strong><small>${hot && node.type === "capability" ? "new authority" : esc(node.type)}${node.severity ? ` · ${esc(node.severity)}` : ""}</small>`;
    canvas.appendChild(el);
  }

  const narrative = $("pathNarrative");
  if (result.primary_path?.length) {
    const pathText = result.primary_path.map(plainToken).filter((x, i, arr) => !x.startsWith("delegate:") && (i === 0 || x !== arr[i - 1])).join(" → ");
    narrative.hidden = false;
    narrative.innerHTML = `<strong>Effective authority path:</strong> ${esc(pathText)}`;
  } else narrative.hidden = true;
}

function renderDecision(result) {
  const badge = $("decisionBadge");
  badge.className = `decision-badge ${decisionClass(result.decision)}`;
  badge.textContent = result.decision;
  $("decisionTitle").textContent = result.decision === "BLOCK" ? "This change crosses a security boundary." : result.decision === "REVIEW" ? "Security review required." : "No blocking security regression found.";
  $("decisionReason").textContent = result.reason;

  const policy = result.policy_authority;
  const policyBox = $("policyEvidence");
  if (policy) {
    policyBox.hidden = false;
    $("policyVersion").textContent = `${policy.name} v${policy.version}`;
    const violation = result.violations?.[0];
    $("policyRule").textContent = violation ? `${violation.id}: ${violation.description}` : "No configured invariant was violated.";
    $("policyMeta").textContent = `Owner: ${policy.owner}${policy.approved_by ? ` · Approved by: ${policy.approved_by}` : ""} · SHA-256 ${policy.digest.slice(0, 12)}…`;
  } else policyBox.hidden = true;

  const capBox = $("newCaps");
  const capList = $("newCapsList");
  capList.innerHTML = "";
  if (result.new_capabilities?.length) {
    capBox.hidden = false;
    result.new_capabilities.forEach((cap) => {
      const row = document.createElement("div");
      row.className = `new-cap ${cap.severity}`;
      row.innerHTML = `<span>${esc(cap.capability)}</span><em>${esc(cap.evidence_level)} · ${esc(cap.severity)}</em>`;
      capList.appendChild(row);
    });
  } else capBox.hidden = true;
}

async function runGuided() {
  const button = $("guidedRun");
  button.disabled = true;
  button.textContent = "Analyzing authority…";
  try {
    const enabled = $("delegationToggle").checked;
    const result = await api("/api/analyze", {
      baseline: examples.baseline,
      candidate: candidateForToggle(enabled),
      policy: examples.policy,
      fail_on: "high",
    });
    lastResult = result;
    renderGraph(result);
    renderDecision(result);
    $("graphLegend").textContent = enabled ? "Candidate · delegation ON" : "No authority change";
  } catch (error) {
    $("decisionBadge").textContent = "ERROR";
    $("decisionBadge").className = "decision-badge block";
    $("decisionTitle").textContent = "Could not analyze this system";
    $("decisionReason").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Analyze change";
  }
}

$("guidedRun").addEventListener("click", runGuided);
$("delegationToggle").addEventListener("change", () => {
  $("guidedRun").textContent = $("delegationToggle").checked ? "Analyze risky change" : "Analyze baseline";
});

function renderEditorResult(result) {
  const box = $("editorResult");
  box.hidden = false;
  const violation = result.violations?.[0];
  box.innerHTML = `
    <div class="card-label">RESULT</div>
    <h3><span class="decision-badge ${decisionClass(result.decision)}">${esc(result.decision)}</span></h3>
    <p class="muted">${esc(result.reason)}</p>
    ${violation ? `<p><strong>${esc(violation.id)}</strong> · ${esc(violation.description)}</p>` : ""}
    <div class="result-grid">
      <div class="result-metric"><strong>${Number(result.summary.structural_changes) || 0}</strong><span>STRUCTURAL CHANGES</span></div>
      <div class="result-metric"><strong>${Number(result.summary.proven_new_capabilities) || 0}</strong><span>NEW CAPABILITIES</span></div>
      <div class="result-metric"><strong>${Number(result.summary.gate_violations) || 0}</strong><span>POLICY VIOLATIONS</span></div>
    </div>`;
}

$("editorRun").addEventListener("click", async () => {
  const status = $("editorStatus");
  status.textContent = "Running deterministic authority analysis…";
  try {
    const result = await api("/api/analyze", {
      baseline: $("baselineEditor").value,
      candidate: $("candidateEditor").value,
      policy: $("policyEditor").value,
      fail_on: "high",
    });
    renderEditorResult(result);
    status.textContent = `Policy: ${result.policy_authority?.name || "external policy"}`;
  } catch (error) {
    $("editorResult").hidden = false;
    $("editorResult").innerHTML = `<div class="decision-badge block">INVALID INPUT</div><p class="muted">${esc(error.message)}</p>`;
    status.textContent = "";
  }
});

document.querySelectorAll("[data-load]").forEach((button) => button.addEventListener("click", () => {
  const key = button.dataset.load;
  $(`${key}Editor`).value = examples[key];
}));

$("runtimeRun").addEventListener("click", async () => {
  const box = $("runtimeResult");
  box.hidden = false;
  box.innerHTML = `<p class="muted">Checking policy and reachability…</p>`;
  try {
    const capability = $("runtimeCapability").value;
    const origin = $("runtimeOrigin").value;
    const result = await api("/api/runtime", {
      spec: examples.candidate,
      policy: examples.policy,
      origin_agent: origin,
      capability,
      executor_agent: capability === "payment.execute" && origin === "procurement" ? "finance" : null,
    });
    box.innerHTML = `
      <div class="big-decision ${decisionClass(result.decision)}">${esc(result.decision)}</div>
      <p>${esc(result.reason)}</p>
      ${result.review ? `<p><strong>Reviewer:</strong> ${esc(result.review.approver)}<br><strong>Lease:</strong> ${Number(result.review.max_uses) || 0} use · ${Number(result.review.expires_minutes) || 0} minutes</p>` : ""}
      ${result.invariant ? `<p><strong>${esc(result.invariant.id)}</strong> · ${esc(result.invariant.description)}</p>` : ""}
      ${result.path?.length ? `<p><strong>Path:</strong> ${esc(result.path.map(plainToken).join(" → "))}</p>` : ""}`;
  } catch (error) {
    box.innerHTML = `<div class="big-decision block">ERROR</div><p>${esc(error.message)}</p>`;
  }
});

async function init() {
  try {
    examples = await api("/api/example");
    $("baselineEditor").value = examples.baseline;
    $("candidateEditor").value = examples.candidate;
    $("policyEditor").value = examples.policy;
  } catch (error) {
    $("decisionReason").textContent = `Could not load example: ${error.message}`;
    return;
  }

  try {
    const initial = await api("/api/analyze", {
      baseline: examples.baseline,
      candidate: candidateForToggle(false),
      policy: examples.policy,
      fail_on: "high",
    });
    renderGraph(initial);
    renderDecision(initial);
  } catch (_) {}
}

init();
