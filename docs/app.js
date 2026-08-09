const githubBase='https://github.com/karteekponnuru/ChangeFence/blob/main/';
const scenarioMeta={
  'procurement-delegation':{title:'Procurement → payment execution',domain:'Finance',change:'+ delegation to Finance Agent',copy:'A new delegation edge lets Procurement reach Finance capabilities, including payment execution.',base:'examples/procurement-base.yaml',candidate:'examples/procurement-candidate.yaml'},
  'support-pii-export':{title:'Support → customer PII export',domain:'Data',change:'+ delegation to Analytics Agent',copy:'A new delegation edge lets Support reach Analytics capabilities, including customer PII export.',base:'examples/support-base.yaml',candidate:'examples/support-candidate.yaml'},
  'coding-production-deploy':{title:'Coding agent → production deploy',domain:'Production',change:'+ deploy tool',copy:'Adding the deploy tool makes production deployment directly reachable by the coding agent.',base:'examples/coding-base.yaml',candidate:'examples/coding-candidate.yaml'},
  'safe-prompt-update':{title:'Prompt-only safe change',domain:'Control',change:'prompt_id updated; authority unchanged',copy:'The prompt reference changed, but no new modeled capability or forbidden path was introduced.',base:'examples/procurement-base.yaml',candidate:'examples/procurement-safe-candidate.yaml'}
};
let selectedScenario='procurement-delegation';
let suiteControls=null;

function setScenario(slug){
  selectedScenario=slug;
  document.querySelectorAll('.scenario-tab').forEach(b=>b.classList.toggle('active',b.dataset.scenario===slug));
  const m=scenarioMeta[slug];
  document.getElementById('scenarioTitle').textContent=m.title;
  document.getElementById('scenarioDomain').textContent=m.domain;
  document.getElementById('scenarioChange').textContent=m.change;
  document.getElementById('scenarioCopy').textContent=m.copy;
  document.getElementById('baseLink').href=githubBase+m.base;
  document.getElementById('candidateLink').href=githubBase+m.candidate;
  document.getElementById('jsonLink').href='demo-data/'+slug+'.json';
  document.getElementById('result').classList.remove('show');
  document.getElementById('runExample').textContent='Load engine result';
}

document.querySelectorAll('.scenario-tab').forEach(btn=>btn.addEventListener('click',()=>setScenario(btn.dataset.scenario)));

async function loadImpact(){
  const button=document.getElementById('runExample');
  button.disabled=true;button.textContent='Loading…';
  try{
    const response=await fetch('demo-data/'+selectedScenario+'.json',{cache:'no-store'});
    if(!response.ok) throw new Error('Result artifact unavailable');
    const data=await response.json();
    const r=data.result;
    const card=document.getElementById('decisionCard');
    card.className='decision '+r.decision.toLowerCase();
    document.getElementById('decisionValue').textContent=r.decision;
    document.getElementById('decisionReason').textContent=r.decision_reason;
    const proven=r.proven_findings||[];
    const critical=proven.find(x=>x.severity==='critical')||proven[0];
    const empty=document.getElementById('emptyResult');
    if(critical){
      document.getElementById('findingTitle').textContent=critical.source_agent+' can newly reach '+critical.capability+'.';
      document.getElementById('findingCopy').textContent=data.plain_english;
      document.getElementById('evidenceBadge').hidden=false;
      document.getElementById('findingPath').hidden=false;
      document.getElementById('findingPath').textContent=critical.path.join('  →  ');
      empty.hidden=true;
    }else{
      document.getElementById('findingTitle').textContent='No new modeled authority was introduced.';
      document.getElementById('findingCopy').textContent=data.plain_english;
      document.getElementById('evidenceBadge').hidden=true;
      document.getElementById('findingPath').hidden=true;
      empty.hidden=false;empty.textContent='The engine found no new reachable capability and no newly violated invariant in deterministic mode.';
    }
    const s=r.summary;
    document.getElementById('metrics').innerHTML=`<span class="metric"><b>${s.structural_changes}</b> structural change${s.structural_changes===1?'':'s'}</span><span class="metric"><b>${s.proven_new_capabilities}</b> PROVEN capability delta</span><span class="metric"><b>${s.gate_violations}</b> gate violation${s.gate_violations===1?'':'s'}</span>`;
    const violation=(r.gate_violations||[])[0];
    const v=document.getElementById('violation');
    if(violation){v.hidden=false;v.textContent=`${violation.id} · ${violation.description}`;}else{v.hidden=true;v.textContent='';}
    document.getElementById('result').classList.add('show');
    button.textContent='Engine result loaded';
  }catch(err){
    document.getElementById('result').classList.add('show');
    document.getElementById('findingTitle').textContent='Could not load the result artifact.';
    document.getElementById('findingCopy').textContent=err.message;
    button.textContent='Try again';
  }finally{button.disabled=false;}
}
document.getElementById('runExample').addEventListener('click',loadImpact);

function renderSuite(module){
  document.querySelectorAll('.suite-btn').forEach(b=>b.classList.toggle('active',b.dataset.module===module));
  const target=document.getElementById('suiteDetail');
  if(module==='impact'){
    target.innerHTML='<h3>Impact</h3><p>The flagship layer. It turns a baseline/candidate change into a capability delta, affected invariants and a PR decision.</p><div class="detail-card"><div class="row"><span>Primary object</span><span class="code">capability delta</span></div><div class="row"><span>Deterministic finding</span><span class="status block">PROVEN / BLOCK</span></div><div class="row"><span>Primary command</span><span class="code">changefence impact</span></div></div>';
    return;
  }
  if(!suiteControls){target.innerHTML='<h3>Loading module evidence…</h3><p>The demo is fetching the suite artifact generated from the repository implementation.</p>';return;}
  if(module==='runtime'){
    const r=suiteControls.runtime_review,rev=r.review;
    target.innerHTML=`<h3>Runtime</h3><p>A pre-action control for custom/local agents. Hard invariants block; configurable rules can require a human owner.</p><div class="detail-card"><div class="row"><span>Actual decision</span><span class="status review">${r.decision}</span></div><div class="row"><span>Causal origin</span><span class="code">${r.origin_agent}</span></div><div class="row"><span>Capability</span><span class="code">${r.capability}</span></div><div class="row"><span>Reviewer</span><span>${rev.approver}</span></div><div class="row"><span>Approval scope</span><span>${rev.max_uses} use · ${rev.expires_minutes} min</span></div></div>`;
    return;
  }
  if(module==='policy'){
    const p=suiteControls.policy_plan.recommendations[0];
    target.innerHTML=`<h3>Policy</h3><p>Impact findings become reviewable control plans. Generated controls are never silently deployed.</p><div class="detail-card"><div class="row"><span>Actual recommendation</span><span class="status review">${p.status}</span></div><div class="row"><span>Intent</span><span>${p.intent}</span></div><div class="row"><span>Triggered by</span><span class="code">${p.triggered_by_invariant}</span></div><div class="row"><span>Auto-deploy</span><span>${p.auto_deploy?'yes':'no'}</span></div></div>`;
    return;
  }
  if(module==='probe'){
    const p=suiteControls.probe;
    target.innerHTML=`<h3>Probe</h3><p>A local LLM generates security test hypotheses aimed only at the change consequences found by Impact, then exports them to existing eval tooling.</p><div class="detail-card"><div class="row"><span>Model path</span><span class="code">${p.engine} · local</span></div><div class="row"><span>Public demo</span><span>${p.status.replaceAll('_',' ')}</span></div><div class="row"><span>Verdict authority</span><span>LLM never decides</span></div><div class="row"><span>Export</span><span class="code">Promptfoo YAML</span></div></div>`;
    return;
  }
  if(module==='ledger'){
    const l=suiteControls.ledger;
    target.innerHTML=`<h3>Ledger</h3><p>Impact and Runtime decisions can be retained as tamper-evident evidence so the security story survives beyond a CI run.</p><div class="detail-card"><div class="row"><span>Status</span><span class="status ok">${l.status}</span></div><div class="row"><span>Format</span><span class="code">${l.format}</span></div><div class="row"><span>Verify</span><span class="code">changefence ledger-verify</span></div></div>`;
  }
}

document.querySelectorAll('.suite-btn').forEach(btn=>btn.addEventListener('click',()=>renderSuite(btn.dataset.module)));

async function loadSuiteControls(){
  try{const response=await fetch('demo-data/suite-controls.json',{cache:'no-store'});if(response.ok)suiteControls=await response.json();}catch(_err){}
  renderSuite(document.querySelector('.suite-btn.active').dataset.module);
}

setScenario(selectedScenario);
renderSuite('impact');
loadSuiteControls();
