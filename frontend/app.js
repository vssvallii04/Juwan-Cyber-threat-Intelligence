/* ── Juwan CTI v3.0 — Frontend Logic & D3 Timeline ── */

const API = "";  // same origin

// ─── Clock ──────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent =
    now.toLocaleTimeString("en-IN", { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();


// ─── Server Health ──────────────────────────────────────────────────
async function checkHealth() {
  try {
    const r = await fetch(`${API}/health`);
    const el = document.getElementById("server-status");
    if (r.ok) {
      el.textContent = "API Online";
      el.style.color = "var(--success)";
    } else {
      el.textContent = "API Error";
      el.style.color = "var(--danger)";
    }
  } catch {
    document.getElementById("server-status").textContent = "Offline";
  }
}
checkHealth();
setInterval(checkHealth, 30000);


// ─── Panel Navigation ────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    item.classList.add("active");
    const panelId = "panel-" + item.dataset.panel;
    const panel = document.getElementById(panelId);
    if (panel) panel.classList.add("active");
    const titles = {
      dashboard: "Dashboard", email: "Email Analysis",
      url: "URL / APK Risk", chat: "Chat Scam Detector",
      voice: "Vishing Analyzer", image: "Deepfake & Image Fraud",
      ensemble: "5-Channel Ensemble", campaigns: "Campaign Intelligence",
    };
    document.getElementById("panel-title").textContent = titles[item.dataset.panel] || "";
    if (item.dataset.panel === "dashboard") loadDashboard();
    if (item.dataset.panel === "campaigns") loadCampaigns();
  });
});


// ─── Result Renderer ─────────────────────────────────────────────────
function renderResult(el, data) {
  el.classList.remove("hidden", "threat-high", "threat-medium", "threat-low", "error");
  const tl = (data.threat_level || "").toUpperCase();
  if (tl === "HIGH") el.classList.add("threat-high");
  else if (tl === "MEDIUM") el.classList.add("threat-medium");
  else el.classList.add("threat-low");

  const icon = data.prediction?.includes("phish") || data.prediction?.includes("scam")
    || data.prediction?.includes("deepfake") || data.prediction?.includes("vishing")
    ? "⚠ THREAT DETECTED" : "✓ CLEAN";

  const lines = [
    `${icon}`,
    `─────────────────────────────────`,
    `Prediction  : ${data.prediction || "—"}`,
    `Confidence  : ${((data.confidence || 0)*100).toFixed(1)}%`,
    `Threat Level: ${data.threat_level || "—"}`,
  ];

  if (data.indicators?.length)
    lines.push(`Indicators  : ${data.indicators.slice(0,8).join(", ")}`);
  if (data.ai_origin?.prediction)
    lines.push(`AI-Origin   : ${data.ai_origin.prediction} (${((data.ai_origin.confidence||0)*100).toFixed(1)}%)`);
  if (data.apk_delivery_risk !== undefined)
    lines.push(`APK Risk    : ${data.apk_delivery_risk ? "YES ⚠" : "No"}`);
  if (data.transcript)
    lines.push(`Transcript  : "${data.transcript.slice(0, 120)}…"`);
  if (data.deepfake)
    lines.push(`Deepfake    : ${((data.deepfake.confidence||0)*100).toFixed(1)}%`);
  if (data.tamper_ela)
    lines.push(`ELA Tamper  : ${((data.tamper_ela.tamper_probability||0)*100).toFixed(1)}%`);
  if (data.qr_found !== undefined)
    lines.push(`QR Found    : ${data.qr_found ? "Yes → " + (data.decoded_url||"") : "No"}`);
  if (data.total_modules_analyzed !== undefined)
    lines.push(`Modules     : ${data.total_modules_analyzed} analyzed`);
  if (data.final_decision)
    lines.push(`Final       : ${data.final_decision.toUpperCase()}`);

  lines.push(`─────────────────────────────────`);
  lines.push(`artifact_id : ${data.artifact_id || "—"}`);

  el.textContent = lines.join("\n");
}

function renderError(el, err) {
  el.classList.remove("hidden");
  el.classList.add("threat-high");
  el.textContent = `Error: ${err}`;
}


// ─── Email ────────────────────────────────────────────────────────────
async function analyzeEmail() {
  const text = document.getElementById("email-input").value;
  const el = document.getElementById("email-result");
  if (!text.trim()) return;
  el.textContent = "Analyzing…"; el.classList.remove("hidden");
  try {
    const r = await fetch(`${API}/analyze/email`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ text }),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}

// ─── URL ──────────────────────────────────────────────────────────────
async function analyzeURL() {
  const url = document.getElementById("url-input").value;
  const apkMode = document.getElementById("apk-mode").checked;
  const el = document.getElementById("url-result");
  if (!url.trim()) return;
  el.textContent = "Analyzing…"; el.classList.remove("hidden");
  const endpoint = apkMode ? "/analyze/url/apk-risk" : "/analyze/url";
  try {
    const r = await fetch(`${API}${endpoint}`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ url }),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}

// ─── Chat ─────────────────────────────────────────────────────────────
async function analyzeChat() {
  const text = document.getElementById("chat-input").value;
  const el = document.getElementById("chat-result");
  if (!text.trim()) return;
  el.textContent = "Analyzing…"; el.classList.remove("hidden");
  try {
    const r = await fetch(`${API}/analyze/chat`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ text }),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}

// ─── Voice ────────────────────────────────────────────────────────────
async function analyzeVoice() {
  const transcript = document.getElementById("voice-input").value;
  const el = document.getElementById("voice-result");
  if (!transcript.trim()) return;
  el.textContent = "Analyzing…"; el.classList.remove("hidden");
  try {
    const r = await fetch(`${API}/analyze/voice`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ transcript }),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}

// ─── Image ────────────────────────────────────────────────────────────
async function analyzeImage() {
  const image_path = document.getElementById("image-input").value;
  const qrMode = document.getElementById("qr-mode").checked;
  const el = document.getElementById("image-result");
  if (!image_path.trim()) return;
  el.textContent = "Analyzing…"; el.classList.remove("hidden");
  const endpoint = qrMode ? "/analyze/qr" : "/analyze/image";
  try {
    const r = await fetch(`${API}${endpoint}`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ image_path }),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}

// ─── Ensemble ─────────────────────────────────────────────────────────
async function analyzeEnsemble() {
  const el = document.getElementById("ensemble-result");
  el.textContent = "Running 5-channel ensemble…"; el.classList.remove("hidden");
  const body = {
    email:            document.getElementById("ens-email").value || null,
    url:              document.getElementById("ens-url").value || null,
    chat:             document.getElementById("ens-chat").value || null,
    voice_transcript: document.getElementById("ens-voice").value || null,
  };
  try {
    const r = await fetch(`${API}/analyze/ensemble`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body),
    });
    renderResult(el, await r.json());
  } catch(e) { renderError(el, e); }
}


// ─── Dashboard ────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const r = await fetch(`${API}/intelligence/campaigns`);
    if (!r.ok) return;
    const data = await r.json();
    const campaigns = data.campaigns || [];
    document.getElementById("val-campaigns").textContent = campaigns.length;
    document.getElementById("val-total").textContent = "—";
    document.getElementById("val-high").textContent = "—";
    document.getElementById("val-medium").textContent = "—";

    renderCampaignList("campaign-list", campaigns.slice(0, 5));
    renderD3Timeline(campaigns);
    updateChannelBars(campaigns);
  } catch(e) {
    console.warn("Dashboard load failed:", e);
  }
}


// ─── Campaigns ────────────────────────────────────────────────────────
async function loadCampaigns() {
  const el = document.getElementById("campaigns-detail");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const r = await fetch(`${API}/intelligence/campaigns?limit=50`);
    if (!r.ok) { el.innerHTML = "<p class='muted'>Database not connected yet.</p>"; return; }
    const data = await r.json();
    renderCampaignList("campaigns-detail", data.campaigns || []);
  } catch(e) {
    el.innerHTML = `<p class='muted'>Error: ${e}</p>`;
  }
}

function renderCampaignList(elId, campaigns) {
  const el = document.getElementById(elId);
  if (!campaigns.length) { el.innerHTML = "<p class='muted'>No campaigns detected yet.</p>"; return; }
  el.innerHTML = campaigns.map(c => `
    <div class="campaign-item" onclick="fetchCampaignDetail('${c.id}')">
      <div class="campaign-name">${c.name || c.id.slice(0,12)}</div>
      <div class="campaign-meta">
        First: ${new Date(c.first_seen).toLocaleDateString()} · Last: ${new Date(c.last_seen).toLocaleDateString()} · ${c.victim_count} IOCs
      </div>
      <div class="campaign-channels">
        ${(c.channels||[]).map(ch=>`<span class="channel-tag">${ch}</span>`).join("")}
      </div>
    </div>
  `).join("");
}

async function fetchCampaignDetail(id) {
  const el = document.getElementById("campaigns-detail");
  try {
    const r = await fetch(`${API}/intelligence/campaigns/${id}`);
    const data = await r.json();
    const c = data.campaign || {};
    const evs = data.ioc_events || [];
    el.innerHTML = `
      <div style="margin-bottom:12px">
        <a href="/taxii/api-root/collections/cti-v3-ioc-store/objects/" target="_blank" class="btn-small">STIX Objects ↗</a>
        <a href="/intelligence/campaigns/${id}/stix" target="_blank" class="btn-small">STIX Bundle ↗</a>
        <button class="btn-small" onclick="loadCampaigns()">← Back</button>
      </div>
      <div class="campaign-name">${c.name}</div>
      <div class="campaign-meta">${evs.length} IOC events · First: ${new Date(c.first_seen).toLocaleDateString()}</div>
      <br/>
      ${evs.slice(0,20).map(e=>`
        <div class="campaign-item" style="cursor:default">
          <div class="campaign-meta">[${e.channel}] ${e.threat_level} · ${(e.confidence*100).toFixed(0)}% · ${new Date(e.timestamp).toLocaleString()}</div>
          <div class="campaign-channels">${(e.indicators||[]).slice(0,5).map(i=>`<span class="channel-tag">${i}</span>`).join("")}</div>
        </div>
      `).join("")}
    `;
  } catch(e) { el.innerHTML = `<p class='muted'>Error: ${e}</p>`; }
}


// ─── Channel Bars ─────────────────────────────────────────────────────
function updateChannelBars(campaigns) {
  const counts = { email:0, url:0, chat:0, voice:0, image:0 };
  campaigns.forEach(c => (c.channels||[]).forEach(ch => {
    if (ch in counts) counts[ch]++;
  }));
  const max = Math.max(...Object.values(counts), 1);
  Object.entries(counts).forEach(([ch, n]) => {
    const pct = Math.round(n / max * 100);
    const bar = document.getElementById(`bar-${ch}`);
    const lbl = document.getElementById(`pct-${ch}`);
    if (bar) bar.style.width = pct + "%";
    if (lbl) lbl.textContent = n;
  });
}


// ─── D3 Campaign Timeline ─────────────────────────────────────────────
function renderD3Timeline(campaigns) {
  const container = document.getElementById("d3-timeline");
  container.innerHTML = "";
  if (!campaigns.length) {
    container.innerHTML = "<p class='muted' style='padding:8px'>No campaigns to display.</p>";
    return;
  }

  const W = container.clientWidth || 700;
  const H = 160;
  const margin = { top: 20, right: 20, bottom: 30, left: 40 };
  const w = W - margin.left - margin.right;
  const h = H - margin.top - margin.bottom;

  const svg = d3.select("#d3-timeline")
    .append("svg")
    .attr("viewBox", `0 0 ${W} ${H}`)
    .attr("preserveAspectRatio", "xMidYMid meet");

  const g = svg.append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

  // Build timeline data: group campaigns per day
  const dayMap = {};
  campaigns.forEach(c => {
    const date = new Date(c.first_seen);
    const key = date.toISOString().slice(0, 10);
    dayMap[key] = (dayMap[key] || 0) + 1;
  });
  const data = Object.entries(dayMap)
    .map(([k, v]) => ({ date: new Date(k), count: v }))
    .sort((a, b) => a.date - b.date);

  if (!data.length) return;

  const x = d3.scaleTime()
    .domain(d3.extent(data, d => d.date))
    .range([0, w]);

  const y = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.count) + 1])
    .range([h, 0]);

  // Gradient
  const defs = svg.append("defs");
  const grad = defs.append("linearGradient")
    .attr("id", "timeline-grad")
    .attr("gradientUnits", "userSpaceOnUse")
    .attr("x1", 0).attr("y1", 0).attr("x2", 0).attr("y2", h);
  grad.append("stop").attr("offset", "0%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.6);
  grad.append("stop").attr("offset", "100%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.05);

  // Area
  const area = d3.area()
    .x(d => x(d.date)).y0(h).y1(d => y(d.count))
    .curve(d3.curveBasis);

  g.append("path")
    .datum(data)
    .attr("fill", "url(#timeline-grad)")
    .attr("d", area);

  // Line
  const line = d3.line()
    .x(d => x(d.date)).y(d => y(d.count))
    .curve(d3.curveBasis);

  g.append("path")
    .datum(data)
    .attr("fill", "none")
    .attr("stroke", "#3b82f6")
    .attr("stroke-width", 2)
    .attr("d", line);

  // Dots
  g.selectAll(".dot")
    .data(data)
    .join("circle")
    .attr("class", "dot")
    .attr("cx", d => x(d.date))
    .attr("cy", d => y(d.count))
    .attr("r", 4)
    .attr("fill", "#3b82f6")
    .attr("stroke", "#0a0d14")
    .attr("stroke-width", 2);

  // X axis
  g.append("g")
    .attr("transform", `translate(0,${h})`)
    .call(d3.axisBottom(x).ticks(5).tickFormat(d3.timeFormat("%b %d")))
    .selectAll("text").attr("fill", "#64748b").style("font-size", "11px");
  g.selectAll(".domain,.tick line").attr("stroke", "#1e2d45");

  // Y axis
  g.append("g")
    .call(d3.axisLeft(y).ticks(3).tickFormat(d => Math.round(d)))
    .selectAll("text").attr("fill", "#64748b").style("font-size", "11px");
  g.selectAll(".domain").attr("stroke", "#1e2d45");
}

// Load dashboard on initial load
loadDashboard();
