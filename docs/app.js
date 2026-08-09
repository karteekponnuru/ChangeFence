const impactButton = document.getElementById('runImpact');
const impactResult = document.getElementById('impactResult');
const runtimeButton = document.getElementById('applyApproval');
let suiteControls = null;

async function getJson(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Could not load ${path}`);
  return response.json();
}

impactButton.addEventListener('click', async () => {
  impactButton.disabled = true;
  impactButton.textContent = 'Running engine-backed example…';
  try {
    const data = await getJson('demo-data/procurement-delegation.json');
    const result = data.result;
    const critical = (result.proven_findings || []).find(item => item.capability === 'payment.execute') || result.proven_findings[0];
    const policy = result.policy_authority;

    document.getElementById('decisionReason').textContent = result.decision_reason;
    document.getElementById('authorityPath').textContent = critical.path.join('  →  ');
    document.getElementById('groundTruth').innerHTML = `
      <div><span>Ground truth</span><strong>${policy.name} v${policy.version}</strong></div>
      <div><span>Rule</span><strong>${result.gate_violations[0].id}</strong></div>
      <div><span>Policy owner</span><strong>${policy.owner}</strong></div>
      <div><span>Policy digest</span><code>${policy.digest.slice(0, 16)}…</code></div>`;
    document.getElementById('impactMetrics').innerHTML = `
      <span><strong>${result.summary.structural_changes}</strong> source changes</span>
      <span><strong>${result.summary.proven_new_capabilities}</strong> new capabilities</span>
      <span><strong>${result.summary.gate_violations}</strong> hard policy violation</span>`;

    impactResult.hidden = false;
    impactButton.textContent = 'Real result loaded';
  } catch (error) {
    impactResult.hidden = false;
    impactResult.innerHTML = `<div class="load-error">${error.message}</div>`;
    impactButton.textContent = 'Try again';
  } finally {
    impactButton.disabled = false;
  }
});

async function loadSuiteControls() {
  if (!suiteControls) suiteControls = await getJson('demo-data/suite-controls.json');
  return suiteControls;
}

runtimeButton.addEventListener('click', async () => {
  runtimeButton.disabled = true;
  runtimeButton.textContent = 'Validating scoped approval…';
  try {
    const controls = await loadSuiteControls();
    const after = controls.runtime_authorized;
    const lease = controls.approval_lease;
    const policy = controls.policy_ground_truth;

    const runtimeCard = document.getElementById('runtimeDecision');
    runtimeCard.classList.add('allowed');
    document.getElementById('runtimeStatus').textContent = after.decision;
    document.getElementById('runtimeCopy').textContent = `Approved by ${after.authorization.approved_by}; the one-use lease has now been consumed.`;

    const detail = document.getElementById('approvalDetail');
    detail.innerHTML = `
      <div><span>Lease</span><strong>${lease.lease_id}</strong></div>
      <div><span>Scoped capability</span><code>${lease.capability}</code></div>
      <div><span>Policy rule</span><strong>${lease.rule_id}</strong></div>
      <div><span>Authority path bound</span><strong>Yes</strong></div>
      <div><span>Uses remaining</span><strong>${after.authorization.uses_remaining}</strong></div>
      <div><span>Ground truth</span><strong>${policy.name} v${policy.version}</strong></div>`;
    detail.hidden = false;
    runtimeButton.textContent = 'Approval lease consumed';
  } catch (error) {
    runtimeButton.textContent = 'Could not load approval example';
  } finally {
    runtimeButton.disabled = false;
  }
});
