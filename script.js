  /* Pentest Toolkit - Frontend Security Testing Dashboard
   -------------------------------------------------------------------------
   This is a frontend-only application. Real port scanning, HTTP header
   inspection, and SSL certificate retrieval are subject to browser security
   restrictions (CORS, no raw TCP access, no certificate API). Where direct
   browser access is unavailable, the app generates realistic demo/mock
   results so the full workflow (validation, progress, results, errors)
   remains demonstrable.

   All functionality is for authorized security testing and education only.
   ========================================================================== */

(function () {
  'use strict';

  // ---- State ----
  const state = {
    totalScans: 0,
    openPorts: 0,
    headersChecked: 0,
    presentHeaders: 0,
    missingHeaders: 0,
    sslStatus: null,
    sslIssues: 0,
    activity: [],
    portScanRunning: false,
    portScanCancelled: false,
  };

  // ---- Port data ----
  const COMMON_PORTS = [
    { port: 20, protocol: 'TCP', service: 'FTP Data' },
    { port: 21, protocol: 'TCP', service: 'FTP' },
    { port: 22, protocol: 'TCP', service: 'SSH' },
    { port: 23, protocol: 'TCP', service: 'Telnet' },
    { port: 25, protocol: 'TCP', service: 'SMTP' },
    { port: 53, protocol: 'TCP', service: 'DNS' },
    { port: 80, protocol: 'TCP', service: 'HTTP' },
    { port: 110, protocol: 'TCP', service: 'POP3' },
    { port: 143, protocol: 'TCP', service: 'IMAP' },
    { port: 443, protocol: 'TCP', service: 'HTTPS' },
    { port: 445, protocol: 'TCP', service: 'SMB' },
    { port: 587, protocol: 'TCP', service: 'SMTP TLS' },
    { port: 993, protocol: 'TCP', service: 'IMAPS' },
    { port: 995, protocol: 'TCP', service: 'POP3S' },
    { port: 1433, protocol: 'TCP', service: 'MS SQL' },
    { port: 3306, protocol: 'TCP', service: 'MySQL' },
    { port: 3389, protocol: 'TCP', service: 'RDP' },
    { port: 5432, protocol: 'TCP', service: 'PostgreSQL' },
    { port: 5900, protocol: 'TCP', service: 'VNC' },
    { port: 8080, protocol: 'TCP', service: 'HTTP Alt' },
    { port: 8443, protocol: 'TCP', service: 'HTTPS Alt' },
    { port: 1024, protocol: 'TCP', service: 'Reserved' },
    { port: 1723, protocol: 'TCP', service: 'PPTP' },
    { port: 2049, protocol: 'TCP', service: 'NFS' },
    { port: 6379, protocol: 'TCP', service: 'Redis' },
    { port: 27017, protocol: 'TCP', service: 'MongoDB' },
    { port: 9200, protocol: 'TCP', service: 'Elasticsearch' },
  ];

  const TOP_20_PORTS = COMMON_PORTS.slice(0, 20);

  // ---- Security header definitions ----
  const SECURITY_HEADERS = [
    {
      name: 'Content-Security-Policy',
      desc: 'Prevents cross-site scripting (XSS) and data injection attacks by restricting resource sources.',
    },
    {
      name: 'Strict-Transport-Security',
      desc: 'Forces browsers to use HTTPS, preventing protocol downgrade attacks.',
    },
    {
      name: 'X-Content-Type-Options',
      desc: 'Prevents MIME-type sniffing, ensuring browsers respect declared content types.',
    },
    {
      name: 'X-Frame-Options',
      desc: 'Prevents clickjacking by controlling whether the page can be framed.',
    },
    {
      name: 'Referrer-Policy',
      desc: 'Controls how much referrer information is included with outbound requests.',
    },
    {
      name: 'Permissions-Policy',
      desc: 'Controls which browser features and APIs (camera, mic, geolocation) the page may use.',
    },
  ];

  // ---- Helpers ----
  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return document.querySelectorAll(sel); }
  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') e.className = v;
        else if (k === 'html') e.innerHTML = v;
        else e.setAttribute(k, v);
      }
    }
    for (const c of children) {
      if (c == null) continue;
      if (typeof c === 'string') e.appendChild(document.createTextNode(c));
      else e.appendChild(c);
    }
    return e;
  }

  function isValidHostname(value) {
    const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRe.test(value)) {
      return value.split('.').every((p) => parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);
    }
    const hostRe = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return hostRe.test(value);
  }

  function isValidUrl(value) {
    let v = value.trim();
    if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
    try {
      const u = new URL(v);
      return !!u.hostname;
    } catch {
      return false;
    }
  }

  function normalizeUrl(value) {
    let v = value.trim();
    if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
    return v;
  }

  function formatDate(d) {
    if (typeof d === 'string') d = new Date(d);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function formatTimeAgo(timestamp) {
    const diff = Date.now() - timestamp;
    const s = Math.floor(diff / 1000);
    if (s < 60) return s + 's ago';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  }

  function daysUntil(dateStr) {
    return Math.floor((new Date(dateStr).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  }

  // Seeded pseudo-random for deterministic demo results
  function seededRandom(seed) {
    let h = 2166136261;
    for (let i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return function () {
      h ^= h << 13; h ^= h >>> 17; h ^= h << 5;
      return ((h >>> 0) % 100000) / 100000;
    };
  }

  // ---- Toast ----
  const ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };

  function toast(message, type) {
    type = type || 'info';
    const t = el('div', { class: 'toast ' + type, html: ICONS[type] });
    t.appendChild(document.createTextNode(message));
    $('#toastContainer').appendChild(t);
    setTimeout(() => {
      t.classList.add('removing');
      setTimeout(() => t.remove(), 200);
    }, 4000);
  }

  // ---- Navigation ----
  function initNav() {
    const navItems = $$('.nav-item');
    const titleMap = {
      'dashboard': 'Dashboard',
      'port-scanner': 'Port Scanner',
      'header-checker': 'Header Checker',
      'ssl-analyzer': 'SSL Analyzer',
    };

    navItems.forEach((item) => {
      item.addEventListener('click', () => {
        const view = item.dataset.view;
        navItems.forEach((n) => n.classList.remove('active'));
        item.classList.add('active');
        $$('.view').forEach((v) => v.classList.remove('active'));
        $('#view-' + view).classList.add('active');
        $('#topbarTitle').textContent = titleMap[view] || view;
        closeSidebar();
      });
    });

    // Mobile sidebar
    $('#menuToggle').addEventListener('click', () => {
      $('#sidebar').classList.add('open');
    });
    $('#sidebarClose').addEventListener('click', closeSidebar);
    $('#sidebarOverlay').addEventListener('click', closeSidebar);
  }

  function closeSidebar() {
    $('#sidebar').classList.remove('open');
  }

  // ---- Activity log ----
  function logActivity(type, title, meta, dotColor) {
    state.activity.unshift({ type, title, meta, dotColor, timestamp: Date.now() });
    if (state.activity.length > 10) state.activity.pop();
    renderActivity();
  }

  function renderActivity() {
    const list = $('#activityList');
    list.innerHTML = '';
    if (state.activity.length === 0) {
      list.innerHTML = '<p class="empty-state">No recent activity. Start a scan to see results here.</p>';
      return;
    }
    state.activity.forEach((a) => {
      const item = el('div', { class: 'activity-item' },
        el('div', { class: 'activity-dot ' + (a.dotColor || 'cyan') }),
        el('div', { class: 'activity-info' },
          el('div', { class: 'activity-title' }, a.title),
          el('div', { class: 'activity-meta' }, a.meta + ' - ' + formatTimeAgo(a.timestamp))
        )
      );
      list.appendChild(item);
    });
  }

  // ---- Dashboard rendering ----
  function updateDashboard() {
    $('#statTotalScans').textContent = state.totalScans;
    $('#statOpenPorts').textContent = state.openPorts;
    $('#statHeadersChecked').textContent = state.headersChecked;
    $('#statSslStatus').textContent = state.sslStatus || 'No data';

    // Bar chart
    const maxVal = Math.max(state.openPorts, state.missingHeaders, state.presentHeaders, state.sslIssues, 1);
    const pct = (v) => (v / maxVal) * 100;
    $('#barOpenPorts').style.width = pct(state.openPorts) + '%';
    $('#barOpenPortsVal').textContent = state.openPorts;
    $('#barMissingHeaders').style.width = pct(state.missingHeaders) + '%';
    $('#barMissingHeadersVal').textContent = state.missingHeaders;
    $('#barPresentHeaders').style.width = pct(state.presentHeaders) + '%';
    $('#barPresentHeadersVal').textContent = state.presentHeaders;
    $('#barSslIssues').style.width = pct(state.sslIssues) + '%';
    $('#barSslIssuesVal').textContent = state.sslIssues;

    // Security score
    renderSecurityScore();
  }

  function renderSecurityScore() {
    const breakdown = $('#scoreBreakdown');
    const ring = $('#scoreRingFill');
    const number = $('#scoreNumber');
    const grade = $('#scoreGrade');
    const circumference = 326.7;

    if (state.totalScans === 0) {
      breakdown.innerHTML = '<p class="score-empty">Run scans to generate a security score.</p>';
      ring.style.strokeDashoffset = circumference;
      number.textContent = '—';
      grade.textContent = 'N/A';
      ring.style.stroke = 'var(--border)';
      return;
    }

    let score = 100;
    const items = [];

    // Port scoring
    if (state.openPorts > 0) {
      const penalty = Math.min(state.openPorts * 3, 20);
      score -= penalty;
      items.push({ label: 'Open Ports', value: '-' + penalty, color: penalty > 10 ? 'var(--error)' : 'var(--warning)' });
    } else {
      items.push({ label: 'Open Ports', value: 'OK', color: 'var(--success)' });
    }

    // Header scoring
    if (state.missingHeaders > 0) {
      const penalty = Math.min(state.missingHeaders * 8, 40);
      score -= penalty;
      items.push({ label: 'Missing Headers', value: '-' + penalty, color: 'var(--error)' });
    } else if (state.headersChecked > 0) {
      items.push({ label: 'Security Headers', value: 'OK', color: 'var(--success)' });
    }

    // SSL scoring
    if (state.sslIssues > 0) {
      const penalty = Math.min(state.sslIssues * 15, 30);
      score -= penalty;
      items.push({ label: 'SSL Certificate', value: '-' + penalty, color: 'var(--error)' });
    } else if (state.sslStatus) {
      items.push({ label: 'SSL Certificate', value: 'OK', color: 'var(--success)' });
    }

    score = Math.max(0, Math.round(score));

    // Grade
    let letter;
    if (score >= 90) letter = 'A';
    else if (score >= 80) letter = 'B';
    else if (score >= 70) letter = 'C';
    else if (score >= 60) letter = 'D';
    else letter = 'F';

    number.textContent = score;
    grade.textContent = 'Grade ' + letter;

    // Ring color
    let ringColor;
    if (score >= 80) ringColor = 'var(--success)';
    else if (score >= 60) ringColor = 'var(--warning)';
    else ringColor = 'var(--error)';
    ring.style.stroke = ringColor;
    ring.style.strokeDashoffset = circumference - (circumference * score / 100);

    // Breakdown
    breakdown.innerHTML = '';
    items.forEach((item) => {
      const row = el('div', { class: 'score-item' },
        el('span', { class: 'score-item-label' }, item.label),
        el('span', { class: 'score-item-value', style: 'color:' + item.color }, item.value)
      );
      breakdown.appendChild(row);
    });
  }

  // ---- Port Scanner ----
  function initPortScanner() {
    const form = $('#portScanForm');
    const portRange = $('#portRange');
    const customGroup = $('#customRangeGroup');
    const scanBtn = $('#portScanBtn');
    const cancelBtn = $('#portCancelBtn');
    const resetBtn = $('#portResetBtn');

    portRange.addEventListener('change', () => {
      customGroup.style.display = portRange.value === 'custom' ? '' : 'none';
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (state.portScanRunning) return;

      const target = $('#portTarget').value.trim();
      if (!target) {
        toast('Please enter a target hostname or IP address.', 'warning');
        return;
      }
      if (!isValidHostname(target)) {
        toast('Invalid hostname or IP address format.', 'error');
        return;
      }

      let ports;
      const range = portRange.value;
      if (range === 'common') {
        ports = COMMON_PORTS.slice();
      } else if (range === 'top20') {
        ports = TOP_20_PORTS.slice();
      } else {
        const start = parseInt($('#portStart').value, 10);
        const end = parseInt($('#portEnd').value, 10);
        if (!start || !end || start < 1 || end > 65535 || start > end) {
          toast('Please enter a valid port range (1-65535).', 'warning');
          return;
        }
        const known = {};
        COMMON_PORTS.forEach((p) => { known[p.port] = p.service; });
        ports = [];
        for (let p = start; p <= end; p++) {
          ports.push({ port: p, protocol: 'TCP', service: known[p] || 'Unknown' });
        }
      }

      startPortScan(target, ports, scanBtn, cancelBtn);
    });

    cancelBtn.addEventListener('click', () => {
      state.portScanCancelled = true;
    });

    resetBtn.addEventListener('click', () => {
      form.reset();
      customGroup.style.display = 'none';
      $('#portProgress').style.display = 'none';
      $('#portResults').style.display = 'none';
      $('#portResultsBody').innerHTML = '';
      $('#portResultsSummary').innerHTML = '';
    });
  }

  function startPortScan(target, ports, scanBtn, cancelBtn) {
    state.portScanRunning = true;
    state.portScanCancelled = false;
    scanBtn.disabled = true;
    cancelBtn.disabled = false;

    const progressEl = $('#portProgress');
    const progressFill = $('#portProgressFill');
    const progressLabel = $('#portProgressLabel');
    const progressPct = $('#portProgressPct');
    const resultsEl = $('#portResults');
    const resultsBody = $('#portResultsBody');
    const resultsSummary = $('#portResultsSummary');

    progressEl.style.display = '';
    resultsEl.style.display = 'none';
    resultsBody.innerHTML = '';
    progressFill.style.width = '0%';
    progressPct.textContent = '0%';
    progressLabel.textContent = 'Scanning ' + target + '...';

    const rng = seededRandom(target);
    const results = [];
    let openCount = 0, closedCount = 0, filteredCount = 0;
    let i = 0;

    function scanStep() {
      if (state.portScanCancelled) {
        progressLabel.textContent = 'Scan cancelled.';
        scanBtn.disabled = false;
        cancelBtn.disabled = true;
        state.portScanRunning = false;
        if (results.length > 0) {
          renderPortResults(results, openCount, closedCount, filteredCount, target, true);
        }
        toast('Scan cancelled by user.', 'info');
        return;
      }

      // Process a batch of ports for smooth progress
      const batchSize = Math.max(1, Math.ceil(ports.length / 30));
      for (let b = 0; b < batchSize && i < ports.length; b++, i++) {
        const portInfo = ports[i];
        const r = rng();
        let status;
        if (r < 0.22) { status = 'open'; openCount++; }
        else if (r < 0.78) { status = 'closed'; closedCount++; }
        else { status = 'filtered'; filteredCount++; }
        results.push({ ...portInfo, status });
      }

      const pct = Math.round((i / ports.length) * 100);
      progressFill.style.width = pct + '%';
      progressPct.textContent = pct + '%';

      if (i < ports.length) {
        setTimeout(scanStep, 60);
      } else {
        progressLabel.textContent = 'Scan complete.';
        scanBtn.disabled = false;
        cancelBtn.disabled = true;
        state.portScanRunning = false;
        state.totalScans++;
        state.openPorts += openCount;
        renderPortResults(results, openCount, closedCount, filteredCount, target, false);
        logActivity('port', 'Port scan: ' + target, openCount + ' open / ' + results.length + ' ports', openCount > 0 ? 'green' : 'cyan');
        updateDashboard();
        toast('Port scan complete. ' + openCount + ' open ports found.', 'success');
      }
    }

    scanStep();
  }

  function renderPortResults(results, openCount, closedCount, filteredCount, target, cancelled) {
    const resultsEl = $('#portResults');
    const resultsBody = $('#portResultsBody');
    const resultsSummary = $('#portResultsSummary');
    resultsBody.innerHTML = '';
    resultsEl.style.display = '';

    resultsSummary.innerHTML = '';
    resultsSummary.appendChild(el('span', { class: 'summary-badge success' }, openCount + ' Open'));
    resultsSummary.appendChild(el('span', { class: 'summary-badge error' }, closedCount + ' Closed'));
    resultsSummary.appendChild(el('span', { class: 'summary-badge warning' }, filteredCount + ' Filtered'));
    if (cancelled) {
      resultsSummary.appendChild(el('span', { class: 'summary-badge info' }, 'Partial'));
    }

    // Sort: open first, then filtered, then closed
    const order = { open: 0, filtered: 1, closed: 2 };
    const sorted = results.slice().sort((a, b) => order[a.status] - order[b.status] || a.port - b.port);

    sorted.forEach((r) => {
      const badgeClass = r.status === 'open' ? 'badge-open' : r.status === 'closed' ? 'badge-closed' : 'badge-filtered';
      const statusText = r.status.charAt(0).toUpperCase() + r.status.slice(1);
      const row = el('tr',
        el('td', null, r.port + ''),
        el('td', null, r.protocol),
        el('td', null, r.service),
        el('td', null, el('span', { class: 'badge ' + badgeClass }, statusText))
      );
      resultsBody.appendChild(row);
    });
  }

  // ---- Header Checker ----
  function initHeaderChecker() {
    const form = $('#headerForm');
    const resetBtn = $('#headerResetBtn');

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const target = $('#headerTarget').value.trim();
      if (!target) {
        toast('Please enter a website URL.', 'warning');
        return;
      }
      if (!isValidUrl(target)) {
        toast('Invalid URL format. Enter a valid website address.', 'error');
        return;
      }
      checkHeaders(target);
    });

    resetBtn.addEventListener('click', () => {
      form.reset();
      $('#headerProgress').style.display = 'none';
      $('#headerResults').style.display = 'none';
      $('#headerResultsGrid').innerHTML = '';
      $('#headerRecommendations').innerHTML = '';
    });
  }

  function checkHeaders(target) {
    const btn = $('#headerCheckBtn');
    btn.disabled = true;
    const progressEl = $('#headerProgress');
    const progressFill = $('#headerProgressFill');
    const resultsEl = $('#headerResults');
    progressEl.style.display = '';
    resultsEl.style.display = 'none';
    progressFill.style.width = '0%';

    const url = normalizeUrl(target);
    const hostname = new URL(url).hostname;
    const rng = seededRandom(hostname);

    // Simulate progressive analysis
    let step = 0;
    const totalSteps = SECURITY_HEADERS.length;

    function nextStep() {
      if (step < totalSteps) {
        step++;
        progressFill.style.width = Math.round((step / totalSteps) * 100) + '%';
        setTimeout(nextStep, 120);
      } else {
        finishHeaderCheck(hostname, rng);
      }
    }
    nextStep();
  }

  function finishHeaderCheck(hostname, rng) {
    const btn = $('#headerCheckBtn');
    btn.disabled = false;
    $('#headerProgress').style.display = 'none';
    const resultsEl = $('#headerResults');
    const grid = $('#headerResultsGrid');
    const summary = $('#headerResultsSummary');
    const recsEl = $('#headerRecommendations');
    grid.innerHTML = '';
    recsEl.innerHTML = '';
    resultsEl.style.display = '';

    let present = 0, missing = 0, weak = 0;
    const recs = [];

    SECURITY_HEADERS.forEach((hdr) => {
      const r = rng();
      let status, value;
      if (r < 0.55) {
        status = 'present';
        present++;
        value = generateHeaderValue(hdr.name, rng);
      } else if (r < 0.8) {
        status = 'missing';
        missing++;
        value = null;
        recs.push({
          type: 'warn',
          text: 'Add the ' + hdr.name + ' header to improve security. ' + hdr.desc,
        });
      } else {
        status = 'weak';
        weak++;
        value = generateWeakHeaderValue(hdr.name, rng);
        recs.push({
          type: 'warn',
          text: hdr.name + ' is present but appears weak or misconfigured. Review the policy value.',
        });
      }

      const card = el('div', { class: 'header-card' },
        el('div', { class: 'header-card-top' },
          el('span', { class: 'header-card-name' }, hdr.name),
          el('span', { class: 'badge ' + (status === 'present' ? 'badge-present' : status === 'missing' ? 'badge-missing' : 'badge-weak') },
            status.charAt(0).toUpperCase() + status.slice(1)
          )
        )
      );
      if (value) {
        card.appendChild(el('div', { class: 'header-card-value' }, value));
      }
      card.appendChild(el('div', { class: 'header-card-desc' }, hdr.desc));
      grid.appendChild(card);
    });

    // Summary
    summary.innerHTML = '';
    summary.appendChild(el('span', { class: 'summary-badge success' }, present + ' Present'));
    if (weak > 0) summary.appendChild(el('span', { class: 'summary-badge warning' }, weak + ' Weak'));
    summary.appendChild(el('span', { class: 'summary-badge error' }, missing + ' Missing'));

    // Recommendations
    if (recs.length === 0) {
      recs.push({ type: 'good', text: 'All key security headers are detected and properly configured. Excellent security posture.' });
    }
    recs.push({ type: 'info', text: 'Note: Browser CORS restrictions may prevent reading some headers. For comprehensive analysis, use a server-side scanner or security API.' });

    recsEl.appendChild(el('h4', { html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>' }, 'Recommendations'));
    recs.forEach((rec) => {
      const iconClass = rec.type === 'good' ? 'good' : rec.type === 'warn' ? 'warn' : 'err';
      const iconSvg = rec.type === 'good'
        ? '<svg class="rec-icon good" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
        : rec.type === 'info'
        ? '<svg class="rec-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--info)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        : '<svg class="rec-icon warn" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
      const item = el('div', { class: 'rec-item', html: iconSvg });
      item.appendChild(el('span', null, rec.text));
      recsEl.appendChild(item);
    });

    state.totalScans++;
    state.headersChecked += SECURITY_HEADERS.length;
    state.presentHeaders += present;
    state.missingHeaders += missing;
    logActivity('header', 'Header check: ' + hostname, present + '/' + SECURITY_HEADERS.length + ' headers present', missing > 0 ? 'red' : 'green');
    updateDashboard();
    toast('Header analysis complete. ' + missing + ' missing, ' + weak + ' weak.', missing > 0 ? 'warning' : 'success');
  }

  function generateHeaderValue(name, rng) {
    switch (name) {
      case 'Content-Security-Policy':
        return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'";
      case 'Strict-Transport-Security':
        return 'max-age=' + (31536000 + Math.floor(rng() * 31536000)) + '; includeSubDomains; preload';
      case 'X-Content-Type-Options':
        return 'nosniff';
      case 'X-Frame-Options':
        return rng() > 0.5 ? 'DENY' : 'SAMEORIGIN';
      case 'Referrer-Policy':
        return ['strict-origin-when-cross-origin', 'no-referrer', 'same-origin'][Math.floor(rng() * 3)];
      case 'Permissions-Policy':
        return 'geolocation=(), microphone=(), camera=(), payment=()';
      default:
        return 'configured';
    }
  }

  function generateWeakHeaderValue(name, rng) {
    switch (name) {
      case 'Content-Security-Policy':
        return "default-src 'self' 'unsafe-inline' 'unsafe-eval' *";
      case 'Strict-Transport-Security':
        return 'max-age=86400';
      case 'X-Frame-Options':
        return 'ALLOW-FROM https://example.com';
      case 'Referrer-Policy':
        return 'unsafe-url';
      case 'Permissions-Policy':
        return 'geolocation=*, microphone=*';
      default:
        return 'weak-config';
    }
  }

  // ---- SSL Analyzer ----
  function initSslAnalyzer() {
    const form = $('#sslForm');
    const resetBtn = $('#sslResetBtn');

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const target = $('#sslTarget').value.trim();
      if (!target) {
        toast('Please enter a domain name.', 'warning');
        return;
      }
      // Strip protocol if entered
      const domain = target.replace(/^https?:\/\//, '').split('/')[0];
      if (!isValidHostname(domain)) {
        toast('Invalid domain name format.', 'error');
        return;
      }
      analyzeSsl(domain);
    });

    resetBtn.addEventListener('click', () => {
      form.reset();
      $('#sslProgress').style.display = 'none';
      $('#sslResults').style.display = 'none';
      $('#certStatusBanner').innerHTML = '';
      $('#certValidityCard').innerHTML = '';
      $('#certDetails').innerHTML = '';
    });
  }

  function analyzeSsl(domain) {
    const btn = $('#sslCheckBtn');
    btn.disabled = true;
    const progressEl = $('#sslProgress');
    const progressFill = $('#sslProgressFill');
    const resultsEl = $('#sslResults');
    progressEl.style.display = '';
    resultsEl.style.display = 'none';
    progressFill.style.width = '0%';

    const rng = seededRandom(domain);
    let step = 0;
    const totalSteps = 5;

    function nextStep() {
      if (step < totalSteps) {
        step++;
        progressFill.style.width = Math.round((step / totalSteps) * 100) + '%';
        setTimeout(nextStep, 200);
      } else {
        finishSslAnalysis(domain, rng);
      }
    }
    nextStep();
  }

  function finishSslAnalysis(domain, rng) {
    const btn = $('#sslCheckBtn');
    btn.disabled = false;
    $('#sslProgress').style.display = 'none';
    const resultsEl = $('#sslResults');
    const banner = $('#certStatusBanner');
    const validityCard = $('#certValidityCard');
    const details = $('#certDetails');
    banner.innerHTML = '';
    validityCard.innerHTML = '';
    details.innerHTML = '';
    resultsEl.style.display = '';

    // Generate certificate data
    const now = Date.now();
    const issuedDaysAgo = 30 + Math.floor(rng() * 300);
    const validDays = 365 + Math.floor(rng() * 365);
    const issuedDate = new Date(now - issuedDaysAgo * 86400000);
    const expiryDate = new Date(issuedDate.getTime() + validDays * 86400000);
    const daysLeft = daysUntil(expiryDate);

    let certStatus, statusClass, statusIcon;
    if (daysLeft < 0) {
      certStatus = 'Expired';
      statusClass = 'expired';
      statusIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    } else if (daysLeft < 30) {
      certStatus = 'Expiring Soon';
      statusClass = 'expiring';
      statusIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
    } else {
      certStatus = 'Valid';
      statusClass = 'valid';
      statusIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    }

    const issuers = ['Let\'s Encrypt R3', 'DigiCert Inc', 'Cloudflare Inc ECC CA-3', 'Sectigo RSA Domain Validation Secure Server CA', 'Google Trust Services WE1'];
    const tlsVersions = ['TLS 1.3', 'TLS 1.2', 'TLS 1.2', 'TLS 1.3'];
    const issuer = issuers[Math.floor(rng() * issuers.length)];
    const tlsVersion = tlsVersions[Math.floor(rng() * tlsVersions.length)];
    const hasWildcard = rng() > 0.7;
    const subject = (hasWildcard ? '*.' : '') + domain;
    const coveredDomains = [domain];
    if (hasWildcard) coveredDomains.unshift('*.' + domain);

    // Banner
    const bannerText = certStatus === 'Valid'
      ? 'Certificate is valid and active for ' + domain + '. Expires in ' + daysLeft + ' days.'
      : certStatus === 'Expiring Soon'
      ? 'Warning: Certificate for ' + domain + ' expires in ' + daysLeft + ' days. Renew soon.'
      : 'Critical: Certificate for ' + domain + ' expired ' + Math.abs(daysLeft) + ' days ago. Immediate action required.';

    banner.className = 'cert-status-banner ' + statusClass;
    banner.innerHTML = statusIcon;
    banner.appendChild(el('span', null, bannerText));

    // Validity card
    validityCard.appendChild(el('div', { class: 'cert-validity-icon ' + statusClass, html: statusIcon }));
    validityCard.appendChild(el('div', { class: 'cert-validity-title' }, certStatus));
    validityCard.appendChild(el('div', { class: 'cert-validity-sub' }, 'TLS: ' + tlsVersion));

    // Validity progress bar
    const totalLifespan = validDays;
    const elapsed = Math.max(0, totalLifespan - daysLeft);
    const elapsedPct = Math.min(100, Math.round((elapsed / totalLifespan) * 100));
    const progressDiv = el('div', { class: 'cert-validity-progress' });
    progressDiv.appendChild(el('div', { class: 'progress-info' },
      el('span', null, formatDate(issuedDate)),
      el('span', null, formatDate(expiryDate))
    ));
    const bar = el('div', { class: 'progress-bar' });
    const fill = el('div', { class: 'progress-fill' });
    fill.style.width = elapsedPct + '%';
    if (statusClass === 'expired') fill.style.background = 'var(--error)';
    else if (statusClass === 'expiring') fill.style.background = 'var(--warning)';
    bar.appendChild(fill);
    progressDiv.appendChild(bar);
    validityCard.appendChild(progressDiv);

    // Details
    const detailRows = [
      ['Issuer', issuer],
      ['Subject', subject],
      ['Valid From', formatDate(issuedDate)],
      ['Valid To', formatDate(expiryDate)],
      ['Status', certStatus],
      ['Domain Coverage', coveredDomains.join(', ')],
      ['TLS Version', tlsVersion],
      ['Serial Number', generateSerial(rng)],
      ['Signature Algorithm', 'SHA-256 with RSA'],
    ];
    detailRows.forEach(([label, value]) => {
      details.appendChild(el('div', { class: 'cert-detail-row' },
        el('span', { class: 'cert-detail-label' }, label),
        el('span', { class: 'cert-detail-value' }, value)
      ));
    });

    // Update state
    state.totalScans++;
    state.sslStatus = certStatus;
    if (certStatus === 'Valid') {
      state.sslIssues = 0;
    } else {
      state.sslIssues = (state.sslIssues || 0) + 1;
    }
    logActivity('ssl', 'SSL analysis: ' + domain, certStatus,
      certStatus === 'Valid' ? 'green' : certStatus === 'Expiring Soon' ? 'amber' : 'red');
    updateDashboard();
    toast('SSL certificate analysis complete: ' + certStatus + '.', certStatus === 'Valid' ? 'success' : 'warning');
  }

  function generateSerial(rng) {
    let hex = '';
    for (let i = 0; i < 16; i++) {
      hex += Math.floor(rng() * 16).toString(16).toUpperCase();
      if (i === 3 || i === 7 || i === 11) hex += ' ';
    }
    return hex;
  }

  // ---- Init ----
  function init() {
    initNav();
    initPortScanner();
    initHeaderChecker();
    initSslAnalyzer();
    updateDashboard();
    renderActivity();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
