/* =========================================================================
   DATA
   ========================================================================= */
const SCENARIOS = {
  paypal: {
    url: "https://paypa1-login-security.com/verify",
    riskScore: 96, riskLevel: "HIGH", brand: "PayPal", brandSimilarity: 94,
    domain: "paypa1-login-security.com",
    signals: [
      { label: "Domain reputation", status: "bad", value: "Suspicious" },
      { label: "Typosquatting", status: "bad", value: "Detected" },
      { label: "HTTPS", status: "good", value: "Valid" },
      { label: "Login form", status: "bad", value: "Detected" },
      { label: "Redirect behavior", status: "warn", value: "Suspicious" },
      { label: "Domain age", status: "bad", value: "Very new (4 days)" },
    ],
    contributions: [
      { label: "Brand impersonation", value: 28 },
      { label: "Domain anomaly", value: 23 },
      { label: "Typosquatting", value: 19 },
      { label: "Login form", value: 15 },
      { label: "Redirect behavior", value: 11 },
    ],
    explanation: "This website closely resembles a trusted brand and combines multiple indicators associated with credential theft.",
    attackConfidence: 94, primaryThreat: "Credential theft",
  },
  microsoft: {
    url: "https://secure-account-verification.example",
    riskScore: 61, riskLevel: "MEDIUM", brand: "Microsoft", brandSimilarity: 58,
    domain: "secure-account-verification.example",
    signals: [
      { label: "Domain reputation", status: "warn", value: "Unproven" },
      { label: "Typosquatting", status: "warn", value: "Possible" },
      { label: "HTTPS", status: "good", value: "Valid" },
      { label: "Login form", status: "warn", value: "Present" },
      { label: "Redirect behavior", status: "bad", value: "Detected" },
      { label: "Domain age", status: "warn", value: "6 months" },
    ],
    contributions: [
      { label: "Redirect behavior", value: 22 },
      { label: "Suspicious URL pattern", value: 18 },
      { label: "Unusual domain", value: 12 },
      { label: "Brand keyword match", value: 9 },
    ],
    explanation: "This page shows some patterns associated with credential-harvesting campaigns, but lacks strong brand-impersonation signals.",
    attackConfidence: 61, primaryThreat: "Possible phishing",
  },
  safe: {
    url: "https://example.com",
    riskScore: 4, riskLevel: "LOW", brand: null, brandSimilarity: 0,
    domain: "example.com",
    signals: [
      { label: "Domain reputation", status: "good", value: "Established" },
      { label: "Typosquatting", status: "good", value: "None detected" },
      { label: "HTTPS", status: "good", value: "Valid" },
      { label: "Login form", status: "good", value: "None" },
      { label: "Redirect behavior", status: "good", value: "Normal" },
      { label: "Domain age", status: "good", value: "20+ years" },
    ],
    contributions: [ { label: "Baseline signal noise", value: 4 } ],
    explanation: "No credential-harvesting patterns, brand impersonation, or anomalous domain behavior were detected.",
    attackConfidence: 4, primaryThreat: "None",
  },
};

const THREAT_TABLE = [
  { domain: "paypa1-login.com", threat: "Brand impersonation", risk: 96, detected: "2m ago" },
  { domain: "secure-microsoft.xyz", threat: "Credential theft", risk: 91, detected: "8m ago" },
  { domain: "account-verify.site", threat: "Phishing", risk: 87, detected: "13m ago" },
  { domain: "chase-secure-update.info", threat: "Brand impersonation", risk: 84, detected: "19m ago" },
  { domain: "docusign-review.co", threat: "Credential theft", risk: 79, detected: "27m ago" },
  { domain: "netflix-billing-fix.net", threat: "Phishing", risk: 73, detected: "41m ago" },
  { domain: "apple-id-locked.support", threat: "Brand impersonation", risk: 90, detected: "52m ago" },
  { domain: "wellsfargo-alert.cc", threat: "Credential theft", risk: 88, detected: "1h ago" },
];

const THREAT_TIMELINE = [12,8,5,9,22,34,41,37,45,30,21,15];
const TIMELINE_LABELS = ["00:00","02:00","04:00","06:00","08:00","10:00","12:00","14:00","16:00","18:00","20:00","22:00"];
const RISK_DIST = [
  { name: "High risk", value: 347, color: "#EF4444" },
  { name: "Medium risk", value: 512, color: "#F59E0B" },
  { name: "Low risk", value: 11983, color: "#22C55E" },
];
const CATEGORIES = [
  { name: "Credential theft", value: 512 },
  { name: "Brand impersonation", value: 421 },
  { name: "Malware delivery", value: 198 },
  { name: "Business email compromise", value: 153 },
];
const TOP_BRANDS = [
  { name: "PayPal", value: 284 },
  { name: "Microsoft", value: 231 },
  { name: "Apple", value: 187 },
  { name: "Chase", value: 152 },
  { name: "DocuSign", value: 118 },
];
const CHART_COLORS = ["#22D3EE","#8B5CF6","#F59E0B","#EF4444"];

const NAV = [
  { id: "landing", label: "Overview", icon: "layout-dashboard" },
  { id: "scanner", label: "URL Scanner", icon: "scan-line" },
  { id: "threats", label: "Threat Intelligence", icon: "radar" },
  { id: "attack", label: "Attack Analysis", icon: "git-branch" },
  { id: "history", label: "History", icon: "history" },
  { id: "settings", label: "Settings", icon: "settings" },
];

/* =========================================================================
   STATE + ROUTER
   ========================================================================= */
let state = {
  page: "landing",
  protection: { realtime:true, warnings:true, brand:true, attackPath:true },
  privacy: { localPreprocessing:true, telemetry:false },
  appearance: "dark",
};
const scanTimers = [];
function clearScanTimers(){ scanTimers.forEach(clearTimeout); scanTimers.length = 0; }

function icon(name, opts){
  opts = opts || {};
  return `<i data-lucide="${name}" class="icon" style="width:${opts.size||16}px;height:${opts.size||16}px;color:${opts.color||'currentColor'}"></i>`;
}
function refreshIcons(){ if(window.lucide) lucide.createIcons(); }

function riskColor(level){
  if(level === "HIGH") return "#EF4444";
  if(level === "MEDIUM") return "#F59E0B";
  return "#22C55E";
}
function riskLevelFromScore(n){ return n>=80?"HIGH":n>=50?"MEDIUM":"LOW"; }
function riskBadgeClass(level){ return level==="HIGH"?"high":level==="MEDIUM"?"medium":"low"; }
function statusIcon(status){
  if(status==="good") return icon("check-circle-2",{size:14,color:"#4ade80"});
  if(status==="warn") return icon("alert-triangle",{size:14,color:"#fbbf24"});
  return icon("x-circle",{size:14,color:"#f87171"});
}
function guessScenario(u){
  const s = (u||"").toLowerCase();
  if(s.includes("paypa1") || s.includes("paypal")) return "paypal";
  if(s.includes("microsoft") || s.includes("secure-account")) return "microsoft";
  return "safe";
}

function pushToast(msg){
  const wrap = document.getElementById("toast-wrap");
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `${icon("zap",{size:14,color:"#67e8f9"})}<span>${msg}</span>`;
  wrap.appendChild(el);
  refreshIcons();
  setTimeout(()=>{ el.style.opacity="0"; el.style.transition="opacity .3s"; setTimeout(()=>el.remove(),300); }, 3200);
}

function goto(page){
  clearScanTimers();
  state.page = page;
  render();
  document.getElementById("mainContent").scrollTop = 0;
}

/* animated number counter */
function animateNumber(el, target, decimals){
  decimals = decimals || 0;
  const duration = 900;
  const start = performance.now();
  function step(ts){
    const progress = Math.min((ts-start)/duration, 1);
    const eased = 1 - Math.pow(1-progress, 3);
    el.textContent = (target*eased).toFixed(decimals);
    if(progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* =========================================================================
   SVG CHART HELPERS (no external chart lib)
   ========================================================================= */
function svgAreaChart(values, labels, opts){
  opts = opts || {};
  const w = opts.width||600, h = opts.height||220, pad = {t:10,r:10,b:24,l:32};
  const max = Math.max(...values)*1.15;
  const innerW = w-pad.l-pad.r, innerH = h-pad.t-pad.b;
  const stepX = innerW/(values.length-1);
  const pts = values.map((v,i)=>[pad.l+i*stepX, pad.t+innerH-(v/max)*innerH]);
  const linePath = pts.map((p,i)=>(i===0?"M":"L")+p[0]+","+p[1]).join(" ");
  const areaPath = linePath + ` L${pts[pts.length-1][0]},${pad.t+innerH} L${pts[0][0]},${pad.t+innerH} Z`;
  const gridLines = [0,0.25,0.5,0.75,1].map(f=>{
    const y = pad.t+innerH*f;
    return `<line x1="${pad.l}" y1="${y}" x2="${w-pad.r}" y2="${y}" stroke="#1C2330" stroke-width="1"/>`;
  }).join("");
  const xlabels = labels.map((l,i)=> i%2===0 ? `<text x="${pad.l+i*stepX}" y="${h-6}" font-size="10" fill="#5C6577" text-anchor="middle" font-family="JetBrains Mono">${l}</text>` : "").join("");
  const dots = pts.map((p,i)=>`<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="#0A0E14" stroke="#22D3EE" stroke-width="2" class="chart-dot" data-i="${i}"/>`).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" style="overflow:visible">
    <defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#22D3EE" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="#22D3EE" stop-opacity="0"/>
    </linearGradient></defs>
    ${gridLines}
    <path d="${areaPath}" fill="url(#areaGrad)" stroke="none"/>
    <path d="${linePath}" fill="none" stroke="#22D3EE" stroke-width="2"/>
    ${dots}
    ${xlabels}
  </svg>`;
}

function svgLineChart(values, labels, color){
  const w=600,h=220,pad={t:10,r:10,b:24,l:32};
  const max = Math.max(...values)*1.15;
  const innerW=w-pad.l-pad.r, innerH=h-pad.t-pad.b;
  const stepX = innerW/(values.length-1);
  const pts = values.map((v,i)=>[pad.l+i*stepX, pad.t+innerH-(v/max)*innerH]);
  const linePath = pts.map((p,i)=>(i===0?"M":"L")+p[0]+","+p[1]).join(" ");
  const gridLines = [0,0.25,0.5,0.75,1].map(f=>{
    const y=pad.t+innerH*f;
    return `<line x1="${pad.l}" y1="${y}" x2="${w-pad.r}" y2="${y}" stroke="#1C2330" stroke-width="1"/>`;
  }).join("");
  const xlabels = labels.map((l,i)=> i%2===0 ? `<text x="${pad.l+i*stepX}" y="${h-6}" font-size="10" fill="#5C6577" text-anchor="middle" font-family="JetBrains Mono">${l}</text>` : "").join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%">${gridLines}<path d="${linePath}" fill="none" stroke="${color}" stroke-width="2.5"/>${xlabels}</svg>`;
}

function svgPieChart(data){
  const w=240,h=220,cx=w/2,cy=h/2,rOuter=80,rInner=52;
  const total = data.reduce((s,d)=>s+d.value,0);
  let angle = -90;
  const paths = data.map(d=>{
    const frac = d.value/total;
    const startAngle = angle;
    const endAngle = angle + frac*360;
    angle = endAngle;
    const toXY = (r,a)=>[cx+r*Math.cos(a*Math.PI/180), cy+r*Math.sin(a*Math.PI/180)];
    const [x1,y1] = toXY(rOuter,startAngle);
    const [x2,y2] = toXY(rOuter,endAngle);
    const [x3,y3] = toXY(rInner,endAngle);
    const [x4,y4] = toXY(rInner,startAngle);
    const large = (endAngle-startAngle) > 180 ? 1 : 0;
    return `<path d="M${x1},${y1} A${rOuter},${rOuter} 0 ${large} 1 ${x2},${y2} L${x3},${y3} A${rInner},${rInner} 0 ${large} 0 ${x4},${y4} Z" fill="${d.color}"/>`;
  }).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="220">${paths}</svg>`;
}

function svgBarChartH(data){ // horizontal bars, categories
  const w=560, h=data.length*44+20, pad={l:150,r:40,t:10};
  const max = Math.max(...data.map(d=>d.value))*1.15;
  const barH = 22;
  const bars = data.map((d,i)=>{
    const y = pad.t + i*44;
    const bw = (d.value/max)*(w-pad.l-pad.r);
    return `<text x="${pad.l-12}" y="${y+barH/2+4}" font-size="12" fill="#8892A3" text-anchor="end" font-family="Inter">${d.name}</text>
    <rect x="${pad.l}" y="${y}" width="${bw}" height="${barH}" rx="4" fill="#22D3EE"/>
    <text x="${pad.l+bw+8}" y="${y+barH/2+4}" font-size="11" fill="#8892A3" font-family="JetBrains Mono">${d.value}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%">${bars}</svg>`;
}

function svgBarChartV(data, colors){
  const w=560,h=220,pad={t:10,r:10,b:36,l:10};
  const max = Math.max(...data.map(d=>d.value))*1.15;
  const innerW=w-pad.l-pad.r, innerH=h-pad.t-pad.b;
  const bw = innerW/data.length*0.55;
  const gap = innerW/data.length;
  const bars = data.map((d,i)=>{
    const bh = (d.value/max)*innerH;
    const x = pad.l + i*gap + (gap-bw)/2;
    const y = pad.t + innerH - bh;
    const c = colors ? colors[i%colors.length] : "#22D3EE";
    return `<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="4" fill="${c}"/>
    <text x="${x+bw/2}" y="${h-8}" font-size="10" fill="#5C6577" text-anchor="middle" font-family="Inter">${d.name.length>10?d.name.slice(0,9)+'…':d.name}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%">${bars}</svg>`;
}

/* =========================================================================
   PAGE RENDERERS
   ========================================================================= */

function renderSidebarNav(){
  document.getElementById("nav").innerHTML = NAV.map(item => `
    <button class="nav-item ${state.page===item.id?'active':''}" data-goto="${item.id}">
      ${icon(item.icon,{size:16})}
      <span>${item.label}</span>
      ${state.page===item.id ? icon('chevron-right',{size:14,color:'inherit'}).replace('class="icon"','class="icon chev"') : ''}
    </button>`).join("");
  document.getElementById("mobileNav").innerHTML = NAV.slice(0,5).map(item=>`
    <button class="${state.page===item.id?'active':''}" data-goto="${item.id}">
      ${icon(item.icon,{size:18})}
      ${item.label.split(" ")[0]}
    </button>`).join("");
}

/* ---- LANDING ---- */
function pageLanding(){
  return `
  <div class="page">
    <div class="hero">
      <div>
        <div class="eyebrow"><span class="pulse-dot"></span> DETECT → EXPLAIN → WARN → PROTECT</div>
        <h1 class="font-display">PhishLens <span style="color:var(--cyan)">AI</span></h1>
        <p class="tagline">See the attack before you click.</p>
        <p class="desc">Real-time, explainable phishing protection powered by multi-layer threat analysis. Existing tools tell you a website is dangerous — PhishLens tells you why.</p>
        <div class="hero-actions">
          <button class="btn btn-primary" data-goto="scanner">Analyze a URL ${icon('arrow-right',{size:16})}</button>
          <button class="btn btn-outline" data-goto="demo">${icon('play',{size:14})} View live demo</button>
        </div>
      </div>
      <div class="browser-wrap">
        <div class="browser-glow"></div>
        <div class="browser">
          <div class="browser-bar">
            <div class="browser-dot"></div><div class="browser-dot"></div><div class="browser-dot"></div>
            <div class="browser-url">${icon('lock',{size:11,color:'#5C6577'})}<span>paypa1-login-security.com</span></div>
          </div>
          <div class="browser-body" id="heroBody"></div>
        </div>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat">${icon('globe',{size:16,color:'#67e8f9'})}<div class="val">12,842</div><div class="lbl">Websites analyzed</div></div>
      <div class="stat">${icon('radar',{size:16,color:'#f87171'})}<div class="val">1,284</div><div class="lbl">Threats detected</div></div>
      <div class="stat">${icon('shield',{size:16,color:'#fbbf24'})}<div class="val">347</div><div class="lbl">High-risk blocked</div></div>
      <div class="stat">${icon('trending-up',{size:16,color:'#4ade80'})}<div class="val">98.2%</div><div class="lbl">Detection rate</div></div>
    </div>
    <p class="demo-label">Prototype data</p>
  </div>`;
}

function runHeroLoop(){
  const stages = ["Scanning...","Domain analysis ✓","Brand similarity ✓","Threat intelligence ✓","Page behavior ✓","Final result"];
  const body = document.getElementById("heroBody");
  if(!body) return;
  let stage = 0;
  function draw(){
    let logHtml = stages.slice(0, stage+1).map((s,i)=>{
      const cls = i<stage ? "done" : (i===stage && stage<stages.length-1 ? "active" : "");
      const marker = i<stage ? icon('check-circle-2',{size:13,color:'#4ade80'}) : (i===stage && stage<stages.length-1 ? '<span class="spinner"></span>' : '');
      return `<div class="row ${cls}">${marker}${s}</div>`;
    }).join("");
    let resultHtml = "";
    if(stage === stages.length-1){
      resultHtml = `<div class="hero-result">
        <div style="display:flex;align-items:flex-end;gap:8px;margin-bottom:4px;">
          <span class="score">96</span><span class="of100">/ 100</span>
        </div>
        <div class="risk-badge high">${icon('alert-triangle',{size:11})} HIGH RISK</div>
        <p style="font-size:14px;color:var(--muted)">Possible impersonation: <strong style="color:var(--text)">PayPal</strong></p>
      </div>`;
    }
    body.innerHTML = `<div class="scan-log">${logHtml}</div>${resultHtml}`;
    refreshIcons();
  }
  draw();
  const interval = setInterval(()=>{
    if(state.page !== "landing"){ clearInterval(interval); return; }
    stage = stage < stages.length-1 ? stage+1 : 0;
    draw();
  }, stage === stages.length-1 ? 1800 : 650);
  // restart pacing correctly: fixed tick, but reset visually
  let count = 0;
  clearInterval(interval);
  const tick = setInterval(()=>{
    if(state.page !== "landing"){ clearInterval(tick); return; }
    if(stage < stages.length-1){ stage++; draw(); }
    else { count++; if(count>=3){ stage=0; count=0; draw(); } }
  }, 650);
}

/* ---- SCANNER ---- */
const SCAN_STAGES = ["URL inspection","Domain analysis","Reputation check","Brand similarity","Page behavior","Risk calculation"];
let scannerState = { scanning:false, result:null, url:"" };

function pageScanner(){
  return `
  <div class="page narrow">
    <h1 class="page-title font-display">Analyze a website</h1>
    <p class="page-sub">Check a URL before you trust it.</p>

    <div class="card" style="padding:20px;margin-top:32px;">
      <div class="scan-input-row">
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div style="display:flex;gap:12px;flex-wrap:wrap;">
            <div class="url-field" style="flex:1;min-width:200px;">
              ${icon('globe',{size:16,color:'#5C6577'})}
              <input id="urlInput" placeholder="Paste a URL..." value="${scannerState.url}" aria-label="URL to analyze"/>
            </div>
            <button class="btn btn-primary" id="analyzeBtn" ${scannerState.scanning?'disabled':''}>${scannerState.scanning?'Analyzing...':'Analyze'}</button>
          </div>
        </div>
      </div>
      <div class="example-row">
        <span class="lbl">Try:</span>
        <button class="chip red-hover" data-scenario="paypal">PayPal phishing demo</button>
        <button class="chip amber-hover" data-scenario="microsoft">Microsoft phishing demo</button>
        <button class="chip green-hover" data-scenario="safe">Safe website demo</button>
      </div>
    </div>

    <div id="scanProgressWrap"></div>
    <div id="scanResultWrap"></div>
  </div>`;
}

function renderScanProgress(stageIdx){
  const wrap = document.getElementById("scanProgressWrap");
  if(!wrap) return;
  if(stageIdx < 0){ wrap.innerHTML = ""; return; }
  wrap.innerHTML = `<div class="card scan-progress fade-in">
    ${SCAN_STAGES.map((s,i)=>{
      const done = i < stageIdx, active = i === stageIdx;
      const marker = done ? icon('check-circle-2',{size:14,color:'#4ade80'}) : active ? '<span class="spinner"></span>' : `<span class="step-circle"></span>`;
      return `<div class="row ${done||active?'active-row':''}">${marker}${s}</div>`;
    }).join("")}
  </div>`;
}

function renderScanResult(){
  const wrap = document.getElementById("scanResultWrap");
  if(!wrap) return;
  if(!scannerState.result){ wrap.innerHTML=""; return; }
  wrap.innerHTML = `<div style="margin-top:24px;">${scanResultCardHtml(scannerState.result, true)}</div>`;
  refreshIcons();
}

function scanResultCardHtml(result, withActions){
  const color = r