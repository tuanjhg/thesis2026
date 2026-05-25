/* PAD-ONAP Topology Demo — frontend logic (systemdesign.md v2.0)
 *
 * Light-theme dashboard: header chips, KPI row, scenario controls,
 * 11-node demo topology (3 layers as compound parents), node details,
 * event timeline. Live updates over /ws.
 */

(() => {
  // ───────────────────────────────────────────────────────────────────────────
  // Sanity: Cytoscape loaded?
  // ───────────────────────────────────────────────────────────────────────────
  if (typeof cytoscape !== 'function') {
    console.error('[PAD] Cytoscape failed to load. Check Network tab.');
    const cy = document.getElementById('cy');
    if (cy) cy.innerHTML =
      '<div style="padding:40px; text-align:center; color:#DC2626;">' +
      '<h3>Cytoscape library failed to load</h3>' +
      '<p>Open DevTools (F12) → Network and re-load. The page tried 3 sources:</p>' +
      '<ol style="text-align:left; display:inline-block;">' +
      '<li><code>/cytoscape.min.js</code> (local, recommended)</li>' +
      '<li><code>cdnjs.cloudflare.com</code> fallback</li>' +
      '<li><code>unpkg.com</code> fallback</li></ol>' +
      '<p>If all three fail, download manually:<br>' +
      '<code>curl -o frontend/static/cytoscape.min.js https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js</code></p>' +
      '</div>';
    return;
  }
  console.log('[PAD] Cytoscape loaded:', cytoscape.version || 'unknown');

  // ───────────────────────────────────────────────────────────────────────────
  // Style constants (mirror style.css palette)
  // ───────────────────────────────────────────────────────────────────────────
  const C = {
    blue: '#2563EB',  cyan: '#06B6D4', purple: '#7C3AED',
    green: '#059669', red: '#DC2626',  orange: '#F97316',
    border: '#E2E8F0', text: '#0F172A', muted: '#64748B',
    layerBg: { L1: '#ECFEFF', L2: '#F5F3FF', L3: '#ECFDF5' },
    layerBorder: { L1: '#06B6D4', L2: '#7C3AED', L3: '#059669' },
  };

  // ───────────────────────────────────────────────────────────────────────────
  // Cytoscape — 11-node demo topology (compound parents for layers)
  // ───────────────────────────────────────────────────────────────────────────
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [],
    style: [
      { selector: 'node', style: {
          'label': 'data(label)', 'color': C.text, 'font-size': 12,
          'font-weight': 650,
          'text-valign': 'bottom', 'text-margin-y': 6, 'text-halign': 'center',
          'background-color': '#fff',
          'border-color': '#CBD5E1', 'border-width': 1.5,
          'z-index': 20,
          'z-compound-depth': 'top',
          'width': 64, 'height': 64,
          'text-wrap': 'wrap', 'text-max-width': 118 } },
      { selector: 'node:parent', style: {
          'label': 'data(label)', 'font-size': 11, 'font-weight': 700,
          'color': C.muted, 'text-valign': 'top', 'text-halign': 'left',
          'text-margin-y': -6, 'text-margin-x': 10,
          'background-opacity': 0.4,
          'border-width': 1, 'border-style': 'dashed', 'padding': 20,
          'z-index': 1,
          'z-compound-depth': 'bottom',
          'shape': 'roundrectangle' } },
      { selector: 'node#L1', style: {
          'background-color': C.layerBg.L1,
          'border-color': C.layerBorder.L1 } },
      { selector: 'node#L2', style: {
          'background-color': C.layerBg.L2,
          'border-color': C.layerBorder.L2 } },
      { selector: 'node#L3', style: {
          'background-color': C.layerBg.L3,
          'border-color': C.layerBorder.L3 } },
      // Node typing → color
      { selector: 'node[type = "users"]',     style: {
          'background-color': '#FEE2E2', 'border-color': C.red } },
      { selector: 'node[type = "router"]',    style: {
          'background-color': '#DBEAFE', 'border-color': C.blue } },
      { selector: 'node[type = "collector"]', style: {
          'background-color': '#CFFAFE', 'border-color': C.cyan } },
      { selector: 'node[type = "kafka"]',     style: {
          'background-color': '#EDE9FE', 'border-color': C.purple } },
      { selector: 'node[type = "flink"]',     style: {
          'background-color': '#EDE9FE', 'border-color': C.purple } },
      { selector: 'node[type = "ai"]',        style: {
          'background-color': '#F3E8FF', 'border-color': C.purple,
          'border-width': 3 } },
      { selector: 'node[type = "dcae"]',      style: {
          'background-color': '#D1FAE5', 'border-color': C.green } },
      { selector: 'node[type = "policy"]',    style: {
          'background-color': '#D1FAE5', 'border-color': C.green } },
      { selector: 'node[type = "so"]',        style: {
          'background-color': '#D1FAE5', 'border-color': C.green } },
      { selector: 'node[type = "cnf"]',       style: {
          'background-color': '#A7F3D0', 'border-color': C.green,
          'border-width': 3 } },
      { selector: 'node[type = "service"]',   style: {
          'background-color': '#FEF3C7', 'border-color': C.orange,
          'border-width': 3 } },
      // Status modifiers
      { selector: 'node.status-active',  style: {
          'border-color': C.blue, 'border-width': 3 } },
      { selector: 'node.status-warn',    style: { 'border-color': C.orange } },
      { selector: 'node.status-error',   style: { 'border-color': C.red } },
      { selector: 'node.selected',  style: {
          'border-color': '#1D4ED8', 'border-width': 4,
          'background-color': '#DBEAFE' } },
      { selector: 'node.narration-focus', style: {
          'border-width': 4, 'border-color': '#1D4ED8',
          'background-color': '#DBEAFE' } },
      { selector: 'node.inactive',  style: { 'opacity': 0.35 } },
      // Edges
      { selector: 'edge', style: {
          'curve-style': 'bezier', 'line-color': '#CBD5E1', 'width': 1.5,
          'z-index': 10,
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#CBD5E1',
          'label': 'data(label)', 'font-size': 9, 'color': C.muted,
          'text-background-color': '#fff', 'text-background-opacity': 0.9,
          'text-background-padding': 2 } },
      { selector: 'edge[type = "attack"]',    style: {
          'line-color': C.red, 'target-arrow-color': C.red,
          'line-style': 'dashed', 'width': 2 } },
      { selector: 'edge[type = "telemetry"]', style: {
          'line-color': C.cyan, 'target-arrow-color': C.cyan, 'width': 2 } },
      { selector: 'edge[type = "ai"]',        style: {
          'line-color': C.purple, 'target-arrow-color': C.purple,
          'width': 2 } },
      { selector: 'edge[type = "onap"]',      style: {
          'line-color': C.green, 'target-arrow-color': C.green, 'width': 2 } },
      { selector: 'edge[type = "mitigation"]', style: {
          'line-color': C.green, 'target-arrow-color': C.green, 'width': 2.5 } },
      { selector: 'edge[type = "protected"]', style: {
          'line-color': C.green, 'target-arrow-color': C.green,
          'line-style': 'solid', 'width': 2 } },
      { selector: 'edge.flowing', style: {
          'line-dash-pattern': [6, 4] } },
      { selector: 'edge.status-active', style: { 'opacity': 1 } },
      { selector: 'edge.status-inactive', style: {
          'opacity': 0.25, 'line-style': 'dashed' } },
      { selector: 'edge.highlighted', style: { 'width': 4 } },
    ],
    layout: { name: 'preset' },
    minZoom: 0.4, maxZoom: 2,
  });
  window.__padCy = cy;

  // ───────────────────────────────────────────────────────────────────────────
  // DOM helpers
  // ───────────────────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  const setHTML = (id, v) => { const el = $(id); if (el) el.innerHTML = v; };
  const fmt = (n, d = 0) => Number(n || 0).toLocaleString(
    undefined, { minimumFractionDigits: d, maximumFractionDigits: d });

  function syncOverlayToTarget(target, overlay, ctx) {
    if (!target || !overlay) return null;
    const parent = overlay.parentElement;
    const targetRect = target.getBoundingClientRect();
    const parentRect = parent.getBoundingClientRect();
    const width = Math.max(1, Math.min(targetRect.width, window.innerWidth * 2));
    const height = Math.max(1, Math.min(targetRect.height, window.innerHeight * 2));

    overlay.style.left = `${targetRect.left - parentRect.left}px`;
    overlay.style.top = `${targetRect.top - parentRect.top}px`;
    overlay.style.width = `${width}px`;
    overlay.style.height = `${height}px`;

    if (overlay instanceof HTMLCanvasElement && ctx) {
      const dpr = window.devicePixelRatio || 1;
      const nextW = Math.round(width * dpr);
      const nextH = Math.round(height * dpr);
      if (overlay.width !== nextW || overlay.height !== nextH) {
        overlay.width = nextW;
        overlay.height = nextH;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    return { width, height };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Topology render
  // ───────────────────────────────────────────────────────────────────────────
  let topologyHash = '';
  function renderTopology(topo) {
    if (!topo || !topo.nodes || !topo.edges) {
      console.warn('[PAD] renderTopology got invalid payload', topo);
      return;
    }
    const sig = JSON.stringify(
      [topo.layers?.map(l => l.id), topo.nodes.map(n => n.id),
       topo.edges.map(e => e.id)]);
    if (sig !== topologyHash) {
      try {
        cy.elements().remove();
        (topo.layers || []).forEach(l => cy.add({
          data: { id: l.id, label: l.label, kind: 'layer' } }));
        topo.nodes.forEach(n => cy.add({
          data: { id: n.id, parent: n.parent, label: n.label,
                  type: n.type, status: n.status, description: n.description },
          position: { x: n.x, y: n.y } }));
        topo.edges.forEach(e => cy.add({
          data: { id: e.id, source: e.source, target: e.target,
                  type: e.type, label: e.label || '', status: e.status || '' } }));
        cy.resize();
        cy.fit(cy.elements().not(':parent'), 90);
        cy.center();
        topologyHash = sig;
        console.log('[PAD] topology rendered',
                    topo.nodes.length, 'nodes,', topo.edges.length, 'edges');
      } catch (err) {
        console.error('[PAD] renderTopology failed:', err);
        console.error('[PAD] payload was:', topo);
      }
    } else {
      // Update statuses only
      topo.nodes.forEach(n => {
        const el = cy.getElementById(n.id);
        if (!el.length) return;
        el.data({ status: n.status, metrics: n.metrics });
        el.removeClass('status-active status-warn status-error inactive');
        if (n.status === 'active') el.addClass('status-active');
        if (n.status === 'warn')   el.addClass('status-warn');
        if (n.status === 'error')  el.addClass('status-error');
      });
      topo.edges.forEach(e => {
        const el = cy.getElementById(e.id);
        if (!el.length) return;
        el.data({ status: e.status });
        el.removeClass('status-active status-inactive flowing');
        if (e.status === 'active')   el.addClass('status-active flowing');
        if (e.status === 'inactive') el.addClass('status-inactive');
      });
      cy.resize();
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // KPIs
  // ───────────────────────────────────────────────────────────────────────────
  function renderKPIs(k) {
    if (!k) return;
    // Traffic
    setText('kpi-traffic-value', fmt(k.traffic_rate_gbps, 2));
    const delta = k.traffic_rate_delta_pct || 0;
    setText('kpi-traffic-sub',
      `${delta >= 0 ? '+' : ''}${delta}% vs 5 min ago`);
    sparkline('spark-traffic', k.traffic_trend, C.blue);

    // Attack score
    setText('kpi-attack-value', fmt(k.attack_score));
    const lab = (k.attack_score_label || 'Low').toLowerCase();
    setHTML('kpi-attack-badge',
      `<span class="badge ${lab}">${k.attack_score_label || 'Low'}</span>`);
    sparkline('spark-attack', k.attack_trend, C.red);

    // Forecast
    setText('kpi-forecast-value', k.forecast_risk || 'Low');
    setText('kpi-forecast-dir', k.forecast_direction || 'stable');
    setText('kpi-forecast-horizon', k.forecast_horizon_s ?? 30);
    sparkline('spark-forecast', k.forecast_trend, C.purple);

    // CNF
    setText('kpi-cnf-value', k.cnf_status || 'Healthy');
    setText('kpi-cnf-counts',
      `${k.cnf_active || 0} Active · ${k.cnf_degraded || 0} Degraded · ${k.cnf_failed || 0} Failed`);
    setText('donut-label',
      `${k.cnf_active || 0}/${k.cnf_desired || 1}`);
    const arc = $('donut-arc');
    if (arc) {
      const pct = k.cnf_desired
        ? Math.min(100, 100 * (k.cnf_active || 0) / k.cnf_desired) : 0;
      arc.setAttribute('stroke-dasharray', `${pct} ${100 - pct}`);
      arc.setAttribute('stroke',
        k.cnf_status === 'Healthy' ? C.green :
        k.cnf_status === 'Degraded' ? C.orange : C.red);
    }
  }

  function sparkline(svgId, values, color) {
    const svg = $(svgId);
    if (!svg || !values || values.length < 2) {
      if (svg) svg.innerHTML = ''; return;
    }
    const w = 100, h = 30, pad = 2;
    const vmin = Math.min(...values), vmax = Math.max(...values);
    const range = vmax - vmin || 1;
    const step = (w - pad * 2) / (values.length - 1);
    const pts = values.map((v, i) => {
      const x = pad + i * step;
      const y = h - pad - ((v - vmin) / range) * (h - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    svg.innerHTML =
      `<polyline points="${pts}" fill="none" stroke="${color}"
                 stroke-width="1.5" stroke-linejoin="round"/>` +
      `<polyline points="${pts} ${pad + (values.length - 1) * step},${h - pad} ${pad},${h - pad}"
                 fill="${color}" fill-opacity="0.08" stroke="none"/>`;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Header chips
  // ───────────────────────────────────────────────────────────────────────────
  function renderHeader(s) {
    const sc = window.__scenarioMap?.[s.scenario];
    setText('chip-scenario',
      `Scenario: ${sc ? sc.name : (s.scenario === 'idle' ? '—' : s.scenario)}`);

    const mode = s.mode || 'ai_assisted';
    const modeChip = $('chip-mode');
    modeChip.textContent = `Mode: ${mode === 'ai_assisted' ? 'AI-assisted' : 'Rule-only'}`;
    modeChip.classList.toggle('rule', mode === 'rule_only');

    const t = s.active_tier ?? 0;
    const tierChip = $('chip-tier');
    tierChip.textContent = `Tier: T${t}`;
    tierChip.className = `chip chip-tier t${t}`;

    const tier = s.active_tier ?? 0;
    const health = $('chip-health');
    health.classList.remove('warn', 'crit');
    if (tier >= 4) {
      health.classList.add('crit');
      health.textContent = 'Critical';
    } else if (tier >= 2) {
      health.classList.add('warn');
      health.textContent = 'Warning';
    } else {
      health.textContent = 'System Healthy';
    }

    setText('ts', new Date().toLocaleTimeString());
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Scenario controls (left panel)
  // ───────────────────────────────────────────────────────────────────────────
  let __activeScenario = null;
  async function loadScenarios() {
    const r = await fetch('/api/scenarios');
    const d = await r.json();
    window.__scenarios = d.scenarios || [];
    window.__scenarioMap = Object.fromEntries(
      window.__scenarios.map(s => [s.id, s]));
    const list = $('scenario-list');
    list.innerHTML = '';
    window.__scenarios.forEach(s => {
      const el = document.createElement('div');
      el.className = 'sc';
      el.dataset.id = s.id;
      el.innerHTML =
        `<span class="id" style="color:${s.color}">${s.id}</span>` +
        `<span class="name">${s.name}</span>` +
        `<span class="tier">${s.tier_label}</span>`;
      el.onclick = () => triggerScenario(s.id);
      list.appendChild(el);
    });
  }

  function setProfileFromScenario(sc) {
    if (!sc) { ['pr-type','pr-intensity','pr-target','pr-duration']
      .forEach(id => setText(id, '—')); return; }
    setText('pr-type',      sc.profile?.attack_type || sc.attack_type);
    setText('pr-intensity', sc.profile?.intensity || '—');
    setText('pr-target',    sc.profile?.target_service || '—');
    setText('pr-duration',  sc.profile?.duration_min
      ? `${sc.profile.duration_min} min` : `${sc.duration_s}s`);
  }

  async function triggerScenario(id) {
    __activeScenario = id;
    document.querySelectorAll('.sc').forEach(el =>
      el.classList.toggle('active', el.dataset.id === id));
    setProfileFromScenario(window.__scenarioMap?.[id]);
    await fetch(`/api/scenario/${id}`, { method: 'POST' });
  }

  $('btn-start').onclick = async () => {
    const id = __activeScenario || 'S3';
    await triggerScenario(id);
  };
  $('btn-stop').onclick = async () => {
    __activeScenario = null;
    document.querySelectorAll('.sc').forEach(el => el.classList.remove('active'));
    setProfileFromScenario(null);
    await fetch('/api/scenario/reset', { method: 'POST' });
  };

  // Topology k switcher — live POST /api/topology/k
  async function refreshTopologyMeta() {
    try {
      const r = await fetch('/api/topology_info');
      const info = await r.json();
      const sel = $('sel-k');
      if (sel) sel.value = String(info.k);
      // Force re-fetch of scenarios (rates / multi-attacker labels change)
      await loadScenarios();
    } catch (_) { /* offline */ }
  }
  $('sel-k').onchange = async (ev) => {
    const k = parseInt(ev.target.value, 10);
    const r = await fetch('/api/topology/k', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ k }),
    });
    if (!r.ok) {
      pushEvent(Date.now() / 1000, 'error',
                `failed to switch k=${k}: ${(await r.json()).detail}`);
      await refreshTopologyMeta();   // revert select to real value
      return;
    }
    pushEvent(Date.now() / 1000, 'mode', `topology k=${k}`);
    await refreshTopologyMeta();
  };

  // AI / rule-only toggles — mutually exclusive
  $('tgl-ai').onchange = async (ev) => {
    if (ev.target.checked) {
      $('tgl-rule').checked = false;
      await fetch('/api/mode', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'ai_assisted' }) });
    }
  };
  $('tgl-rule').onchange = async (ev) => {
    if (ev.target.checked) {
      $('tgl-ai').checked = false;
      await fetch('/api/mode', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'rule_only' }) });
    } else {
      $('tgl-ai').checked = true;
      await fetch('/api/mode', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'ai_assisted' }) });
    }
  };

  // ───────────────────────────────────────────────────────────────────────────
  // Node details (right panel)
  // ───────────────────────────────────────────────────────────────────────────
  let __selectedNode = null;

  // Per-node-type renderers (systemdesign.md §9)
  const METRIC_FIELDS = {
    users:      [['attack_type','Attack type'], ['rate_pps','Rate']],
    router:    [['in_pps','In pps'], ['out_pps','Out pps'],
                ['telemetry_export','Telemetry export']],
    collector: [['input','Input'], ['sampling_ms','Sampling (ms)'],
                ['export_target','Export target']],
    kafka:     [['topic','Topic'], ['lag','Lag'],
                ['throughput_pps','Throughput pps']],
    flink:     [['window_s','Window (s)'], ['slide_s','Slide (s)'],
                ['features_per_sec','Features/s']],
    ai:        [['attack_score','Attack score'], ['confidence','Confidence'],
                ['forecast_horizon_s','Forecast horizon (s)'],
                ['forecast_risk','Forecast risk'], ['model','Model']],
    dcae:      [['events_in','Events ingested'], ['related_loop','Loop']],
    policy:    [['tier','Selected tier'], ['rule_matched','Rule matched'],
                ['decision_basis','Decision basis']],
    so:        [['vnf_name','VNF'], ['action','Action'],
                ['replica_target','Target replicas']],
    cnf:       [['replica','Replicas'], ['mode','Mode'],
                ['action','Action']],
    service:   [['status_text','Status'], ['rps','Requests/s']],
  };

  function renderNodeDetail(detail) {
    const body = $('rd-body');
    if (!detail) {
      body.innerHTML =
        '<div class="rd-empty muted">Select a topology node to see its runtime details.</div>';
      setText('rd-hint', 'click any node');
      return;
    }
    setText('rd-hint', detail.id);
    const pill = (detail.status || 'idle').toLowerCase();
    let html = '';
    html += `<div class="rd-title">${detail.label} `+
            `<span class="pill ${pill}">${detail.status || 'idle'}</span></div>`;
    html += `<div class="rd-layer">${detail.id} · ${
      ({L1:'Network Layer', L2:'Streaming & AI Layer',
        L3:'ONAP Closed Loop'}[detail.parent] || detail.parent)
    }</div>`;
    if (detail.description) {
      html += `<div class="rd-desc">${detail.description}</div>`;
    }
    const fields = METRIC_FIELDS[detail.type] || [];
    const metrics = detail.metrics || {};
    if (fields.length) {
      html += '<div class="rd-section-title">Runtime metrics</div>';
      fields.forEach(([key, label]) => {
        const v = metrics[key];
        const disp = v === undefined || v === null ? '—' : v;
        html += `<dl class="rd-metric"><dt>${label}</dt><dd>${disp}</dd></dl>`;
      });
    }
    if (detail.related_events?.length) {
      html += '<div class="rd-section-title">Recent events</div>';
      detail.related_events.slice().reverse().forEach(ev => {
        html += `<dl class="rd-metric">`+
                `<dt>${new Date(ev.ts * 1000).toLocaleTimeString()}</dt>`+
                `<dd>${ev.kind}</dd></dl>`;
      });
    }
    body.innerHTML = html;
  }

  async function showNodeDetail(nodeId) {
    if (!nodeId) { renderNodeDetail(null); return; }
    __selectedNode = nodeId;
    cy.nodes().removeClass('selected');
    cy.getElementById(nodeId).addClass('selected');
    try {
      const r = await fetch(`/api/node/${nodeId}`);
      if (r.ok) renderNodeDetail(await r.json());
    } catch (_) { /* offline */ }
    // Highlight upstream/downstream edges
    cy.edges().removeClass('highlighted');
    cy.getElementById(nodeId).connectedEdges().addClass('highlighted');
    // Tell backend (optional)
    fetch('/api/node/select', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: nodeId }) }).catch(()=>{});
  }

  cy.on('tap', 'node', (ev) => {
    const n = ev.target;
    if (n.isParent()) return;
    showNodeDetail(n.id());
  });
  cy.on('tap', (ev) => {
    if (ev.target === cy) {
      __selectedNode = null;
      cy.nodes().removeClass('selected');
      cy.edges().removeClass('highlighted');
      renderNodeDetail(null);
    }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Event timeline (bottom)
  // ───────────────────────────────────────────────────────────────────────────
  const EVENT_TITLE = {
    telemetry_received: 'Telemetry received',
    attack_score:       'Attack score updated',
    forecast_update:    'Forecast updated',
    forecast_horizon:   'Forecast horizon',
    policy_decision:    'Policy decision',
    tier_decision:      'Mitigation tier set',
    cnf_deployed:       'CNF deployed',
    scenario_start:     'Scenario started',
    mode_change:        'Mode changed',
  };

  function classifyEvent(kind) {
    const k = (kind || '').toLowerCase();
    if (k.includes('telemetry')) return 'telemetry';
    if (k.includes('attack')) return 'attack';
    if (k.includes('forecast')) return 'forecast';
    if (k.includes('policy') || k.includes('tier')) return 'tier';
    if (k.includes('cnf') || k.includes('vnf')) return 'cnf';
    if (k.includes('mode')) return 'mode';
    if (k.includes('scenario')) return 'scenario';
    return 'info';
  }

  let __seenEvents = new Set();
  function renderTimeline(events) {
    const ol = $('timeline-list');
    const auto = $('tl-auto').checked;
    events = events || [];
    events.forEach(ev => {
      const key = `${ev.ts}|${ev.kind}|${JSON.stringify(ev)}`;
      if (__seenEvents.has(key)) return;
      __seenEvents.add(key);
      const li = document.createElement('li');
      const cls = classifyEvent(ev.kind);
      li.className = `k-${cls}`;
      li.dataset.related = ev.related_node || '';
      const ts = new Date(ev.ts * 1000).toLocaleTimeString();
      const title = EVENT_TITLE[ev.kind] || ev.kind;
      const extra = Object.entries(ev).filter(([k]) =>
        !['ts', 'kind', 'related_node'].includes(k))
        .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
        .join(', ');
      li.innerHTML =
        `<div class="tl-ts">${ts}</div>` +
        `<div class="tl-title">${title}</div>` +
        `<div class="tl-desc">${extra || '—'}</div>`;
      li.onclick = () => {
        document.querySelectorAll('#timeline-list li').forEach(x =>
          x.classList.remove('active'));
        li.classList.add('active');
        if (li.dataset.related) showNodeDetail(li.dataset.related);
      };
      ol.appendChild(li);
    });
    while (ol.children.length > 200) ol.removeChild(ol.firstChild);
    if (auto) ol.scrollLeft = ol.scrollWidth;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Cytoscape #2 — fat-tree fabric panel (physical attack path visualization)
  // ───────────────────────────────────────────────────────────────────────────
  const cyFabric = cytoscape({
    container: document.getElementById('cy-fabric'),
    elements: [],
    layout: { name: 'preset' },
    style: [
      { selector: 'node', style: {
          'label': 'data(label)', 'color': C.text, 'font-size': 9,
          'text-valign': 'center', 'text-halign': 'center',
          'background-color': '#fff',
          'border-color': '#CBD5E1', 'border-width': 1,
          'z-index': 10,
          'width': 22, 'height': 22 } },
      { selector: 'node[kind = "core"]', style: {
          'background-color': '#DBEAFE', 'border-color': C.blue,
          'border-width': 1.5, 'shape': 'round-rectangle',
          'width': 34, 'height': 22 } },
      { selector: 'node[kind = "agg"]', style: {
          'background-color': '#EDE9FE', 'border-color': C.purple,
          'shape': 'round-rectangle', 'width': 32, 'height': 22 } },
      { selector: 'node[kind = "edge"]', style: {
          'background-color': '#CFFAFE', 'border-color': C.cyan,
          'shape': 'round-rectangle', 'width': 32, 'height': 20 } },
      { selector: 'node[kind = "host"]', style: {
          'background-color': '#D1FAE5', 'border-color': C.green,
          'shape': 'ellipse', 'width': 20, 'height': 20, 'font-size': 8 } },
      { selector: 'node[role = "attacker"]', style: {
          'background-color': '#FECACA', 'border-color': C.red,
          'border-width': 3, 'width': 26, 'height': 26 } },
      { selector: 'node[role = "victim"]', style: {
          'background-color': '#FED7AA', 'border-color': C.orange,
          'border-width': 3, 'width': 26, 'height': 26 } },
      { selector: 'edge', style: {
          'curve-style': 'straight',
          'line-color': '#E2E8F0', 'width': 1,
          'z-index': 1,
          'target-arrow-shape': 'none' } },
      { selector: 'edge.on-path', style: {
          'line-color': C.red, 'width': 2.5,
          'line-style': 'dashed',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': C.red,
          'arrow-scale': 1.15,
          'source-endpoint': 'outside-to-node',
          'target-endpoint': 'outside-to-node' } },
      { selector: 'edge.on-path.flowing', style: {
          'line-dash-pattern': [6, 4] } },
    ],
    minZoom: 0.5, maxZoom: 3,
    autoungrabify: true,         // hosts are immobile (it's a network map)
  });
  window.__padCyFabric = cyFabric;

  // Fabric particle engine (separate canvas overlay)
  let fabricFx = null;
  let fabricFxCtx = null;
  let fabricParticles = [];
  let fabricLastFrame = performance.now();
  function ensureFabricCanvas() {
    if (fabricFx) return;
    const wrap = document.getElementById('fabric-section');
    if (!wrap) return;
    fabricFx = document.createElement('canvas');
    Object.assign(fabricFx.style, {
      position: 'absolute',
      pointerEvents: 'none',
      zIndex: '2',
    });
    wrap.style.position = 'relative';
    wrap.appendChild(fabricFx);
    fabricFxCtx = fabricFx.getContext('2d');
    const resize = () => syncOverlayToTarget($('cy-fabric'), fabricFx, fabricFxCtx);
    new ResizeObserver(resize).observe($('cy-fabric'));
    setTimeout(resize, 50);
  }

  function fabricFxLoop() {
    if (fabricFxCtx) {
      const now = performance.now();
      const dt = Math.min(50, now - fabricLastFrame) / 1000;
      fabricLastFrame = now;
      fabricFxCtx.clearRect(0, 0, fabricFx.width, fabricFx.height);
      const survivors = [];
      for (const p of fabricParticles) {
        p.t += 0.5 * dt;
        if (p.t >= 1) continue;
        const e = cyFabric.getElementById(p.edgeId);
        if (!e.length) continue;
        const s = e.source().renderedPosition();
        const t = e.target().renderedPosition();
        const x = s.x + (t.x - s.x) * p.t;
        const y = s.y + (t.y - s.y) * p.t;
        fabricFxCtx.beginPath();
        fabricFxCtx.fillStyle = '#DC2626';
        fabricFxCtx.shadowColor = '#DC2626';
        fabricFxCtx.shadowBlur = 5;
        fabricFxCtx.arc(x, y, 3, 0, Math.PI * 2);
        fabricFxCtx.fill();
        survivors.push(p);
      }
      fabricParticles = survivors.slice(-200);
    }
    requestAnimationFrame(fabricFxLoop);
  }
  requestAnimationFrame(fabricFxLoop);

  // Renderer for fat-tree fabric
  let fabricHash = '';
  function renderFabric(fab) {
    if (!fab || !fab.nodes) return;
    ensureFabricCanvas();
    const pathSig = (fab.edges || [])
      .filter(e => e.on_path)
      .sort((a, b) => (a.path_order ?? 0) - (b.path_order ?? 0))
      .map(e => `${e.path_source || e.source}>${e.path_target || e.target}`)
      .join('|');
    const sig = `${fab.k}|${fab.nodes.length}|${fab.attacker}|${fab.victim}|${pathSig}`;
    if (sig !== fabricHash) {
      cyFabric.elements().remove();
      fab.nodes.forEach(n => cyFabric.add({
        data: { id: n.id, label: n.label, kind: n.kind,
                role: n.role || '', pod: n.pod ?? -1 },
        position: { x: n.x, y: n.y } }));
      fab.edges.forEach(e => {
        const source = e.on_path && e.path_source ? e.path_source : e.source;
        const target = e.on_path && e.path_target ? e.path_target : e.target;
        cyFabric.add({
          data: { id: e.id, source, target,
                  on_path: e.on_path, path_order: e.path_order ?? -1 } });
      });
      cyFabric.resize();
      cyFabric.fit(undefined, 18);
      cyFabric.center();
      fabricHash = sig;
    } else {
      // Update node roles (attacker/victim) on host-name change
      fab.nodes.forEach(n => {
        const el = cyFabric.getElementById(n.id);
        if (el.length) el.data('role', n.role || '');
      });
    }
    // Highlight path
    cyFabric.edges().removeClass('on-path flowing');
    fab.edges.forEach(e => {
      const el = cyFabric.getElementById(e.id);
      if (el.length && e.on_path) {
        el.addClass('on-path');
        if (fab.path_active) el.addClass('flowing');
      }
    });
    // Spawn particles along path edges when traffic flows
    if (fab.path_active) {
      const onPath = fab.edges
        .filter(e => e.on_path)
        .sort((a, b) => (a.path_order ?? 0) - (b.path_order ?? 0));
      const spawnRate = fab.particles || 2;
      const spawnN = Math.max(1, Math.round(spawnRate / 5)); // soft
      onPath.forEach(e => {
        for (let i = 0; i < spawnN; i++) {
          if (Math.random() < 0.4) fabricParticles.push({ edgeId: e.id, t: Math.random() * 0.05 });
        }
      });
    }
    // Update meta label
    const pathLabel = Array.isArray(fab.path_nodes) && fab.path_nodes.length
      ? ` · ${fab.path_nodes.join(' → ')}`
      : '';
    const pathNote = fab.path_note ? ` · ${fab.path_note}` : '';
    setText('fabric-meta',
      `fat-tree k=${fab.k} · ${fab.n_hosts} hosts · ` +
      `${fab.attacker || '—'} → ${fab.victim || '—'}${pathLabel}${pathNote}`);
  }

  cyFabric.on('pan zoom resize', () => { fabricParticles = []; });

  // ───────────────────────────────────────────────────────────────────────────
  // Particle engine — canvas overlay synced with Cytoscape pan/zoom.
  // Draws colored dots traveling source → target on every active edge.
  // ───────────────────────────────────────────────────────────────────────────
  const fx = $('cy-fx');
  const fxCtx = fx.getContext('2d');
  const ppsLayer = $('edge-labels');
  const fxState = {
    enabled: true,
    particles: [],          // {edgeId, t, color, size, speed}
    edgeMeta: new Map(),    // edgeId → {spawnRate, color, lastSpawnT}
    lastFrame: performance.now(),
  };

  const EDGE_PARTICLE_COLOR = {
    attack:     '#DC2626',
    telemetry:  '#06B6D4',
    ai:         '#7C3AED',
    onap:       '#059669',
    mitigation: '#059669',
    protected:  '#10B981',
  };

  function fxResize() {
    syncOverlayToTarget($('cy'), fx, fxCtx);
    syncOverlayToTarget($('cy'), ppsLayer, null);
  }
  new ResizeObserver(fxResize).observe($('cy'));
  setTimeout(fxResize, 50);

  function updateEdgeMeta(edges) {
    fxState.edgeMeta.clear();
    edges.forEach(e => {
      if (e.status !== 'active' || !(e.particles > 0)) return;
      fxState.edgeMeta.set(e.id, {
        rate: e.particles,
        color: EDGE_PARTICLE_COLOR[e.type] || '#94A3B8',
        size: e.type === 'attack' ? 3.5 :
              e.type === 'mitigation' ? 3.5 : 2.5,
        speed: e.type === 'mitigation' ? 0.45 :
               e.type === 'attack' ? 0.55 : 0.35,
      });
    });
  }

  function edgeEndpoints(edgeId) {
    const e = cy.getElementById(edgeId);
    if (!e.length) return null;
    const s = e.source().renderedPosition();
    const t = e.target().renderedPosition();
    return { sx: s.x, sy: s.y, tx: t.x, ty: t.y };
  }

  function fxLoop() {
    const now = performance.now();
    const dt = Math.min(50, now - fxState.lastFrame) / 1000;
    fxState.lastFrame = now;
    fxCtx.clearRect(0, 0, fx.width, fx.height);

    if (!fxState.enabled) {
      requestAnimationFrame(fxLoop);
      return;
    }

    // 1. Spawn new particles per edge based on spawn rate
    fxState.edgeMeta.forEach((meta, edgeId) => {
      meta.lastSpawnT = (meta.lastSpawnT || 0) + dt;
      const interval = 1 / meta.rate;
      while (meta.lastSpawnT >= interval) {
        fxState.particles.push({
          edgeId, t: 0,
          color: meta.color, size: meta.size, speed: meta.speed,
        });
        meta.lastSpawnT -= interval;
      }
    });

    // 2. Advance + draw each particle; remove finished ones
    const survivors = [];
    for (const p of fxState.particles) {
      p.t += p.speed * dt;
      if (p.t >= 1) continue;
      const endp = edgeEndpoints(p.edgeId);
      if (!endp) continue;
      const x = endp.sx + (endp.tx - endp.sx) * p.t;
      const y = endp.sy + (endp.ty - endp.sy) * p.t;
      fxCtx.beginPath();
      fxCtx.fillStyle = p.color;
      fxCtx.shadowColor = p.color;
      fxCtx.shadowBlur = 6;
      fxCtx.arc(x, y, p.size, 0, Math.PI * 2);
      fxCtx.fill();
      survivors.push(p);
    }
    fxState.particles = survivors;

    // Cap memory: hard limit 600 particles on screen
    if (fxState.particles.length > 600) {
      fxState.particles = fxState.particles.slice(-600);
    }
    requestAnimationFrame(fxLoop);
  }
  fxCtx.shadowBlur = 0;
  requestAnimationFrame(fxLoop);

  // Reset particle positions on pan/zoom (cheaper than syncing each frame)
  cy.on('pan zoom resize', () => {
    fxState.particles = [];
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Live pps labels on edges
  // ───────────────────────────────────────────────────────────────────────────
  let ppsEnabled = true;

  function fmtPps(n) {
    if (!n || n < 1) return '';
    if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k pps`;
    return `${Math.round(n)} pps`;
  }

  function renderPpsLabels(edges) {
    ppsLayer.innerHTML = '';
    if (!ppsEnabled) return;
    edges.forEach(e => {
      if (e.status !== 'active') return;
      const txt = fmtPps(e.pps || 0);
      if (!txt) return;
      const endp = edgeEndpoints(e.id);
      if (!endp) return;
      const mx = (endp.sx + endp.tx) / 2;
      const my = (endp.sy + endp.ty) / 2 - 8;
      const tag = document.createElement('div');
      tag.className = `edge-pps ${e.type}`;
      tag.textContent = txt;
      tag.style.left = `${mx}px`;
      tag.style.top  = `${my}px`;
      ppsLayer.appendChild(tag);
    });
  }

  // Re-render labels on cytoscape viewport change.
  // Exclude 'render' — Cytoscape fires it ~60fps during animations.
  let __ppsDebounce = 0;
  cy.on('pan zoom resize', () => {
    cancelAnimationFrame(__ppsDebounce);
    __ppsDebounce = requestAnimationFrame(() => {
      if (window.__lastEdges) renderPpsLabels(window.__lastEdges);
    });
  });

  // Toggle handlers
  $('tgl-particles').onchange = (ev) => {
    fxState.enabled = ev.target.checked;
    if (!fxState.enabled) fxCtx.clearRect(0, 0, fx.width, fx.height);
  };
  $('tgl-pps').onchange = (ev) => {
    ppsEnabled = ev.target.checked;
    if (window.__lastEdges) renderPpsLabels(window.__lastEdges);
  };

  // ───────────────────────────────────────────────────────────────────────────
  // Step explainer card
  // ───────────────────────────────────────────────────────────────────────────
  let lastStepNum = 0;
  function renderNarration(n) {
    if (!n) return;
    setText('step-num', `${n.step}/${n.total}`);
    setText('step-title', n.title || '—');
    setText('step-body', n.body || '');
    const card = $('step-card');
    if (n.step !== lastStepNum) {
      card.classList.remove('pulse-update');
      // Force reflow then re-add to retrigger animation
      void card.offsetWidth;
      card.classList.add('pulse-update');
      lastStepNum = n.step;
    }
    // Camera nudge: highlight the focused node
    if (n.focus_node) {
      cy.nodes().removeClass('narration-focus');
      const node = cy.getElementById(n.focus_node);
      if (node.length) node.addClass('narration-focus');
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Pipeline trace strip (waterfall)
  // ───────────────────────────────────────────────────────────────────────────
  function renderTrace(trace) {
    if (!trace || !trace.length) return;
    const bars = $('trace-bars');
    const axis = $('trace-axis');
    const total = Math.max(100,
      trace.reduce((m, t) => Math.max(m, t.t_start_ms + t.duration_ms), 0));
    bars.innerHTML = '';
    trace.forEach((row, i) => {
      const div = document.createElement('div');
      div.className = `trace-row ${row.stage === 'fastpath' ? 'fast' :
                                    row.stage === 'slowpath' ? 'slow' : ''}`;
      div.style.top = `${i * 13}px`;
      const startPct = (row.t_start_ms / total) * 100;
      const widthPct = Math.max(0.8, (row.duration_ms / total) * 100);
      div.innerHTML =
        `<span class="trace-label">${row.label}</span>` +
        `<div class="trace-track">` +
          `<div class="trace-bar ${row.status}" ` +
              `style="left:${startPct}%; width:${widthPct}%">` +
            `${row.duration_ms > 0 ? row.duration_ms + ' ms' : ''}` +
          `</div>` +
        `</div>`;
      bars.appendChild(div);
    });
    bars.style.height = `${trace.length * 13}px`;

    // Axis ticks: 0, 25%, 50%, 75%, 100%
    axis.innerHTML = '';
    [0, 0.25, 0.5, 0.75, 1].forEach(p => {
      const t = document.createElement('span');
      t.className = 'tick';
      t.style.left = `calc(100px + (100% - 100px) * ${p})`;
      t.textContent = `${Math.round(p * total)} ms`;
      axis.appendChild(t);
    });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Topology hook — capture edges for label/particle layers
  // ───────────────────────────────────────────────────────────────────────────
  const origRenderTopology = renderTopology;
  renderTopology = function (topo) {
    origRenderTopology(topo);
    window.__lastEdges = topo.edges;
    updateEdgeMeta(topo.edges);
    renderPpsLabels(topo.edges);
    renderNarration(topo.narration);
    renderTrace(topo.trace);
    renderFabric(topo.fabric);
  };

  // ───────────────────────────────────────────────────────────────────────────
  // WebSocket live push
  // ───────────────────────────────────────────────────────────────────────────
  function applyState(s) {
    if (!s) return;
    renderHeader(s);
    renderKPIs(s.kpis);
    renderTimeline(s.history);
    if (s.scenario && s.scenario !== 'idle') {
      __activeScenario = s.scenario;
      document.querySelectorAll('.sc').forEach(el =>
        el.classList.toggle('active', el.dataset.id === s.scenario));
      setProfileFromScenario(window.__scenarioMap?.[s.scenario]);
    }
    const aiOn = s.mode !== 'rule_only';
    $('tgl-ai').checked   = aiOn;
    $('tgl-rule').checked = !aiOn;
    if (__selectedNode) showNodeDetail(__selectedNode);
  }

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.topology) renderTopology(msg.topology);
        if (msg.state)    applyState(msg.state);
      } catch (e) { console.error(e); }
    };
    ws.onclose = () => setTimeout(connect, 2000);
  }

  function setupViewControls() {
    const params = new URLSearchParams(location.search);
    const prefs = {
      focus: params.get('focus') === '1' || params.get('focus') === 'topology',
      kpis: true,
      panels: true,
      timeline: true,
    };
    const setActive = (id, active) => {
      const btn = $(id);
      if (btn) btn.classList.toggle('active', active);
    };
    const refreshGraphs = () => {
      cy.resize();
      cy.fit(cy.elements().not(':parent'), prefs.focus ? 55 : 90);
      cy.center();
      cyFabric.resize();
      cyFabric.fit(undefined, prefs.focus ? 28 : 18);
      cyFabric.center();
      fxResize();
      if (fabricFxCtx && fabricFx) {
        syncOverlayToTarget($('cy-fabric'), fabricFx, fabricFxCtx);
      }
      if (window.__lastEdges) renderPpsLabels(window.__lastEdges);
    };
    const applyViewControls = () => {
      document.body.classList.toggle('focus-view', prefs.focus);
      document.body.classList.toggle('hide-kpis', !prefs.kpis);
      document.body.classList.toggle('hide-panels', !prefs.panels);
      document.body.classList.toggle('hide-timeline', !prefs.timeline);
      setActive('btn-view-focus', prefs.focus);
      setActive('btn-view-kpis', prefs.kpis);
      setActive('btn-view-panels', prefs.panels);
      setActive('btn-view-timeline', prefs.timeline);
      setTimeout(refreshGraphs, 120);
    };
    [
      ['btn-view-focus', 'focus'],
      ['btn-view-kpis', 'kpis'],
      ['btn-view-panels', 'panels'],
      ['btn-view-timeline', 'timeline'],
    ].forEach(([id, key]) => {
      const btn = $(id);
      if (btn) btn.onclick = () => {
        prefs[key] = !prefs[key];
        applyViewControls();
      };
    });
    applyViewControls();
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Bootstrap
  // ───────────────────────────────────────────────────────────────────────────
  refreshTopologyMeta();   // syncs sel-k + scenario list with server's PAD_K
  setupViewControls();
  fetch('/api/topology').then(r => r.json()).then(renderTopology);
  fetch('/api/state').then(r => r.json()).then(applyState);
  connect();
})();
