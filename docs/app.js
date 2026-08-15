(() => {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";
  const state = {
    scope: "192.168.50.0/24",
    selectedIp: "192.168.50.40",
    showLabels: true,
    filter: "",
    hosts: [
      {
        ip: "192.168.50.1",
        name: "gateway",
        type: "router",
        vendor: "Generic Router",
        mac: "02:50:00:00:00:01",
        risk: 12,
        baseline: "accepted",
        visible: true,
        x: 50,
        y: 44,
        reasons: ["Gateway role observed in representative inventory"],
        services: [{ port: 53, proto: "tcp", name: "dns" }, { port: 443, proto: "tcp", name: "https" }],
        cve: null,
        notes: "Representative gateway for the sample subnet."
      },
      {
        ip: "192.168.50.12",
        name: "workstation-01",
        type: "workstation",
        vendor: "Generic Workstation",
        mac: "02:50:00:00:00:12",
        risk: 28,
        baseline: "accepted",
        visible: true,
        x: 31,
        y: 24,
        reasons: ["SMB service represented", "Interactive workstation role"],
        services: [{ port: 22, proto: "tcp", name: "ssh" }, { port: 445, proto: "tcp", name: "smb" }],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.21",
        name: "phone-01",
        type: "mobile",
        vendor: "Generic Mobile",
        mac: "02:50:00:00:00:21",
        risk: 8,
        baseline: "accepted",
        visible: true,
        x: 69,
        y: 22,
        reasons: ["No represented exposed services"],
        services: [],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.34",
        name: "printer-01",
        type: "printer",
        vendor: "Generic Printer",
        mac: "02:50:00:00:00:34",
        risk: 42,
        baseline: "pending",
        visible: true,
        x: 22,
        y: 55,
        reasons: ["Identity change awaiting operator review", "Web admin service represented"],
        services: [{ port: 80, proto: "tcp", name: "http" }, { port: 9100, proto: "tcp", name: "jetdirect" }],
        cve: null,
        notes: "Pending baseline review is intentionally represented."
      },
      {
        ip: "192.168.50.40",
        name: "nas-01",
        type: "server",
        vendor: "Generic NAS",
        mac: "02:50:00:00:00:40",
        risk: 67,
        baseline: "accepted",
        visible: true,
        x: 76,
        y: 55,
        reasons: ["SMB service represented", "Administrative web service represented", "Representative CVE correlation exists"],
        services: [{ port: 22, proto: "tcp", name: "ssh" }, { port: 443, proto: "tcp", name: "https" }, { port: 445, proto: "tcp", name: "smb" }],
        cve: { id: "CVE-REP-2026-0040", score: 7.4, severity: "HIGH", note: "Representative correlation only; not queried from this browser." },
        notes: "Elevated-risk sample host used to exercise investigation workflows."
      },
      {
        ip: "192.168.50.51",
        name: "media-01",
        type: "media",
        vendor: "Generic Media Device",
        mac: "02:50:00:00:00:51",
        risk: 14,
        baseline: "accepted",
        visible: true,
        x: 48,
        y: 73,
        reasons: ["Media service represented"],
        services: [{ port: 8008, proto: "tcp", name: "media-control" }],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.61",
        name: "sensor-01",
        type: "iot",
        vendor: "Generic IoT",
        mac: "02:50:00:00:00:61",
        risk: 52,
        baseline: "accepted",
        visible: true,
        x: 15,
        y: 77,
        reasons: ["Legacy plaintext service represented", "IoT role increases review priority"],
        services: [{ port: 23, proto: "tcp", name: "telnet" }],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.73",
        name: "laptop-02",
        type: "workstation",
        vendor: "Generic Laptop",
        mac: "02:50:00:00:00:73",
        risk: 24,
        baseline: "accepted",
        visible: true,
        x: 85,
        y: 78,
        reasons: ["SSH service represented"],
        services: [{ port: 22, proto: "tcp", name: "ssh" }],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.84",
        name: "tablet-01",
        type: "mobile",
        vendor: "Generic Tablet",
        mac: "02:50:00:00:00:84",
        risk: 6,
        baseline: "accepted",
        visible: true,
        x: 56,
        y: 12,
        reasons: ["No represented exposed services"],
        services: [],
        cve: null,
        notes: ""
      },
      {
        ip: "192.168.50.92",
        name: "unclassified-92",
        type: "unknown",
        vendor: "Unknown",
        mac: "02:50:00:00:00:92",
        risk: 58,
        baseline: "pending",
        visible: false,
        x: 88,
        y: 36,
        reasons: ["New identity represented", "Not yet accepted into baseline"],
        services: [],
        cve: null,
        notes: ""
      }
    ],
    edges: [
      ["192.168.50.1", "192.168.50.12"],
      ["192.168.50.1", "192.168.50.21"],
      ["192.168.50.1", "192.168.50.34"],
      ["192.168.50.1", "192.168.50.40"],
      ["192.168.50.1", "192.168.50.51"],
      ["192.168.50.1", "192.168.50.61"],
      ["192.168.50.1", "192.168.50.73"],
      ["192.168.50.1", "192.168.50.84"],
      ["192.168.50.1", "192.168.50.92"]
    ],
    events: [],
    jobs: [],
    reports: [],
    traps: [
      { id: "rep-trap-01", port: 2222, kind: "ssh-banner", state: "representative", hits: 2 },
      { id: "rep-trap-02", port: 8088, kind: "http-decoy", state: "representative", hits: 1 }
    ],
    diff: {
      added: ["192.168.50.34"],
      removed: [],
      changed: ["192.168.50.40"]
    }
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    return node;
  }

  function nowTime(offsetMinutes = 0) {
    const d = new Date(Date.now() + offsetMinutes * 60000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  }

  function addEvent(kind, message, offsetMinutes = 0) {
    state.events.unshift({ time: nowTime(offsetMinutes), kind, message, representative: true });
    state.events = state.events.slice(0, 80);
    renderEvidence();
  }

  function addJob(label, target, finalMessage) {
    const id = `job-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const job = { id, time: nowTime(), label, target, status: "running", message: `Representative ${label.toLowerCase()} queued for ${target}.` };
    state.jobs.unshift(job);
    renderEvidence();
    setTimeout(() => {
      job.status = "success";
      job.message = finalMessage;
      renderEvidence();
    }, 420);
    return job;
  }

  function visibleHosts() {
    return state.hosts.filter(host => host.visible);
  }

  function hostByIp(ip) {
    return state.hosts.find(host => host.ip === ip);
  }

  function riskClass(risk) {
    if (risk >= 60) return "high";
    if (risk >= 35) return "medium";
    return "low";
  }

  function graphRiskClass(risk) {
    if (risk >= 60) return "risk-high";
    if (risk >= 35) return "risk-medium";
    return "";
  }

  function renderGraph() {
    const svg = $("#topologySvg");
    svg.replaceChildren();
    const width = 1000;
    const height = 640;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    const map = new Map(state.hosts.map(host => [host.ip, host]));
    const edgeLayer = svgEl("g", { "aria-hidden": "true" });
    state.edges.forEach(([a, b]) => {
      const h1 = map.get(a);
      const h2 = map.get(b);
      if (!h1 || !h2 || !h1.visible || !h2.visible) return;
      const line = svgEl("line", {
        x1: h1.x * 10,
        y1: h1.y * 6.4,
        x2: h2.x * 10,
        y2: h2.y * 6.4,
        class: `edge${h2.risk >= 60 ? " hot" : ""}`
      });
      edgeLayer.appendChild(line);
    });
    svg.appendChild(edgeLayer);

    const nodeLayer = svgEl("g");
    visibleHosts().forEach(host => {
      const group = svgEl("g", {
        class: `graph-node ${graphRiskClass(host.risk)}${host.baseline === "pending" ? " pending" : ""}${state.selectedIp === host.ip ? " selected" : ""}`,
        transform: `translate(${host.x * 10} ${host.y * 6.4})`,
        tabindex: "0",
        role: "button",
        "aria-label": `${host.name}, ${host.ip}, risk ${host.risk}`,
        "data-ip": host.ip
      });
      group.appendChild(svgEl("circle", { class: "node-hit", r: 24 }));
      group.appendChild(svgEl("circle", { class: "node-ring", r: 18 }));
      group.appendChild(svgEl("circle", { class: "node-core", r: 5 }));
      const name = svgEl("text", { x: 27, y: -2 });
      name.textContent = host.name;
      const ip = svgEl("text", { x: 27, y: 12, class: "ip-label" });
      ip.textContent = host.ip;
      if (!state.showLabels) {
        name.setAttribute("display", "none");
        ip.setAttribute("display", "none");
      }
      group.append(name, ip);
      group.addEventListener("click", () => selectHost(host.ip, true));
      group.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectHost(host.ip, true);
        }
      });
      nodeLayer.appendChild(group);
    });
    svg.appendChild(nodeLayer);
    applyGraphFilter();
    $("#hostCount").textContent = String(visibleHosts().length);
  }

  function applyGraphFilter() {
    const q = state.filter.trim().toLowerCase();
    $$(".graph-node").forEach(node => {
      const host = hostByIp(node.dataset.ip);
      const haystack = `${host.name} ${host.ip} ${host.type} ${host.vendor}`.toLowerCase();
      node.classList.toggle("hidden-by-filter", Boolean(q) && !haystack.includes(q));
    });
  }

  function selectHost(ip, openOnMobile = false) {
    const host = hostByIp(ip);
    if (!host || !host.visible) return;
    state.selectedIp = ip;
    renderGraph();
    renderHostDetail();
    if (openOnMobile && window.matchMedia("(max-width: 760px)").matches) openPanel("host");
  }

  function renderHostDetail() {
    const host = hostByIp(state.selectedIp);
    const root = $("#hostDetail");
    root.replaceChildren();
    if (!host || !host.visible) {
      root.appendChild(el("div", "empty-hint", "Select a representative host from the topology or search results."));
      return;
    }

    const head = el("div", "host-head");
    const identity = el("div");
    identity.append(el("div", "host-name", host.name), el("div", "host-ip", `${host.ip} · ${host.type}`));
    const risk = el("div", `risk-pill ${riskClass(host.risk)}`);
    risk.append(el("b", "", String(host.risk)), el("span", "", "RISK"));
    head.append(identity, risk);
    root.appendChild(head);

    const idCard = el("section", "detail-card");
    idCard.appendChild(el("div", "section-title", "Identity / represented evidence"));
    const grid = el("div", "detail-grid");
    [["Vendor", host.vendor], ["MAC", host.mac], ["Baseline", host.baseline], ["Scope", state.scope]].forEach(([label, value]) => {
      const item = el("div", "detail-item");
      item.append(el("span", "", label), el("b", "", value));
      grid.appendChild(item);
    });
    idCard.appendChild(grid);
    root.appendChild(idCard);

    const riskCard = el("section", "detail-card");
    riskCard.appendChild(el("div", "section-title", "Risk reasons"));
    const reasons = el("div", "reason-list");
    host.reasons.forEach(reason => reasons.appendChild(el("div", "reason-item", reason)));
    riskCard.appendChild(reasons);
    root.appendChild(riskCard);

    const svcCard = el("section", "detail-card");
    svcCard.appendChild(el("div", "section-title", "Services / existing representative state"));
    const services = el("div", "service-list");
    if (!host.services.length) services.appendChild(el("div", "empty-hint", "No representative service evidence loaded for this host."));
    host.services.forEach(service => {
      const row = el("div", "service-item");
      row.append(el("code", "", `${service.port}/${service.proto}`), el("span", "", service.name));
      services.appendChild(row);
    });
    svcCard.appendChild(services);
    const svcActions = el("div", "inline-actions");
    const serviceButton = el("button", "small-button", "Service Scan");
    serviceButton.disabled = true;
    serviceButton.title = "Self-hosted runtime required by site_capabilities.json";
    const cveButton = el("button", "small-button", "CVE Scan");
    cveButton.disabled = true;
    cveButton.title = "Self-hosted runtime required by site_capabilities.json";
    svcActions.append(serviceButton, cveButton);
    svcCard.append(svcActions, el("div", "action-note", "Hosted mode can inspect representative service/CVE state but cannot execute service fingerprinting or CVE correlation."));
    if (host.cve) {
      const cve = el("div", "evidence-item");
      cve.append(el("code", "", host.cve.id), el("span", "", `${host.cve.severity} ${host.cve.score} — ${host.cve.note}`));
      svcCard.appendChild(cve);
    }
    root.appendChild(svcCard);

    const baselineCard = el("section", "detail-card");
    baselineCard.appendChild(el("div", "section-title", "Baseline decision"));
    const baselineText = el("div", "action-note", host.baseline === "pending" ? "This representative identity is awaiting an explicit operator decision." : `Current session state: ${host.baseline}.`);
    const baselineActions = el("div", "inline-actions");
    const accept = el("button", "small-button primary", "Accept");
    const defer = el("button", "small-button", "Defer");
    accept.disabled = host.baseline === "accepted";
    defer.disabled = host.baseline === "deferred";
    accept.addEventListener("click", () => updateBaseline(host.ip, "accepted"));
    defer.addEventListener("click", () => updateBaseline(host.ip, "deferred"));
    baselineActions.append(accept, defer);
    baselineCard.append(baselineText, baselineActions, el("div", "action-note", "Representative session mutation only; nothing is persisted as LANimals evidence."));
    root.appendChild(baselineCard);

    const notesCard = el("section", "detail-card");
    notesCard.appendChild(el("div", "section-title", "Operator notes"));
    const textarea = el("textarea", "notes-area");
    textarea.value = host.notes;
    textarea.setAttribute("aria-label", `Notes for ${host.ip}`);
    const save = el("button", "small-button primary", "Save session note");
    save.style.marginTop = "6px";
    save.addEventListener("click", () => {
      host.notes = textarea.value;
      addEvent("NOTE", `Session-only representative note updated for ${host.ip}.`);
      toast("Session note saved", "Stored only in this page session; no LANimals evidence was written.");
    });
    notesCard.append(textarea, save);
    root.appendChild(notesCard);

    const liveOnlyCard = el("section", "detail-card");
    liveOnlyCard.appendChild(el("div", "section-title", "Self-hosted-only operations"));
    const liveActions = el("div", "inline-actions");
    ["VirusTotal", "Trap Deploy", "Anomaly", "Watchdog"].forEach(label => {
      const button = el("button", "small-button", label);
      button.disabled = true;
      button.title = "Unavailable without the LANimals local runtime";
      liveActions.appendChild(button);
    });
    liveOnlyCard.append(liveActions, el("div", "action-note", "These controls stay disabled here because the public site has no local API connection and no visitor-LAN access."));
    root.appendChild(liveOnlyCard);
  }

  function updateBaseline(ip, decision) {
    const host = hostByIp(ip);
    if (!host) return;
    host.baseline = decision;
    if (decision === "accepted") host.risk = Math.max(0, host.risk - 12);
    addEvent("BASELINE", `${ip} ${decision} in representative page session.`);
    addJob(`Baseline ${decision}`, ip, `Representative baseline decision applied to ${ip}; session memory only.`);
    renderGraph();
    renderHostDetail();
    toast(`Baseline ${decision}`, `${ip} updated in representative session state.`);
  }

  function runRepresentativeAction(action) {
    const scope = state.scope;
    switch (action) {
      case "discovery": {
        const hidden = state.hosts.find(host => !host.visible);
        addJob("Discovery", scope, `Representative discovery completed for ${scope}.`);
        setTimeout(() => {
          if (hidden) {
            hidden.visible = true;
            state.diff.added = [hidden.ip];
            addEvent("DISCOVERY", `Representative host ${hidden.ip} appeared inside ${scope}.`);
            renderGraph();
            renderHostDetail();
          } else {
            addEvent("DISCOVERY", `Representative discovery refreshed ${visibleHosts().length} hosts inside ${scope}.`);
          }
        }, 460);
        toast("Representative Discovery", `Target: ${scope}. No network request was made.`);
        break;
      }
      case "arp":
        addJob("ARP Refresh", scope, `Representative ARP state refreshed for ${visibleHosts().length} hosts.`);
        addEvent("ARP", `Representative neighbor state refreshed for ${scope}; no live ARP executed.`);
        toast("Representative ARP refresh", "In-memory scenario updated; visitor LAN was not touched.");
        break;
      case "hostmap":
        addJob("Host Map", scope, `Representative host map rebuilt from current session inventory.`);
        addEvent("HOSTMAP", `Representative topology rebuilt from ${visibleHosts().length} session hosts.`);
        renderGraph();
        toast("Host map rebuilt", "Topology reflects representative session inventory.");
        break;
      case "rogue": {
        const candidate = state.hosts.find(host => host.visible && host.ip === "192.168.50.34");
        if (candidate) candidate.baseline = "pending";
        addJob("Rogue Detection", scope, "Representative identity-change review state refreshed.");
        addEvent("ROGUE", "Representative identity change remains pending for printer-01.");
        renderGraph();
        renderHostDetail();
        switchTab("baseline");
        toast("Representative rogue check", "One identity change is queued for explicit baseline review.");
        break;
      }
      case "rescore":
        visibleHosts().forEach(host => {
          const baselinePenalty = host.baseline === "pending" ? 12 : host.baseline === "deferred" ? 7 : 0;
          const servicePenalty = Math.min(28, host.services.length * 7);
          const reasonPenalty = Math.min(28, Math.max(0, host.reasons.length - 1) * 9);
          const cvePenalty = host.cve ? 18 : 0;
          host.risk = Math.min(100, Math.max(4, 6 + baselinePenalty + servicePenalty + reasonPenalty + cvePenalty));
        });
        addJob("Risk Rescore", "persisted_hosts (representative)", "Representative risk scores recomputed from session evidence.");
        addEvent("RISK", "Representative risk scores recalculated from current session evidence." );
        renderGraph();
        renderHostDetail();
        toast("Risk scores updated", "Representative session state only.");
        break;
      case "diff":
        addEvent("DIFF", "Representative observation diff opened; read-only inspection does not advance state.");
        switchTab("audit");
        toast("Observation diff", "Showing the last two representative observation states.");
        break;
      case "audit":
        addEvent("AUDIT", "Representative security audit summary opened." );
        switchTab("audit");
        break;
      case "traps":
        switchTab("traps");
        break;
      case "report":
        createRepresentativeReport();
        break;
      default:
        break;
    }
  }

  function renderEvidence() {
    renderEvents();
    renderJobs();
    renderBaseline();
    renderTraps();
    renderReports();
    renderAudit();
    updateCounts();
  }

  function renderEvents() {
    const root = $("#eventsPanel");
    root.replaceChildren();
    state.events.forEach(item => {
      const row = el("div", "event-row");
      row.append(el("span", "row-time", item.time), el("span", "row-kind", item.kind), el("span", "row-message", item.message), el("span", "row-badge", "REPRESENTATIVE"));
      root.appendChild(row);
    });
  }

  function renderJobs() {
    const root = $("#jobsPanel");
    root.replaceChildren();
    if (!state.jobs.length) {
      root.appendChild(el("div", "empty-hint", "No representative operator jobs have been started in this page session."));
      return;
    }
    state.jobs.forEach(job => {
      const row = el("div", `job-row job-${job.status}`);
      row.append(el("span", "row-time", job.time), el("span", "row-kind", job.status.toUpperCase()), el("span", "row-message", `${job.label} · ${job.message}`), el("span", "row-badge", "SESSION"));
      root.appendChild(row);
    });
  }

  function renderBaseline() {
    const root = $("#baselinePanel");
    root.replaceChildren();
    const rows = visibleHosts().filter(host => host.baseline !== "accepted");
    if (!rows.length) {
      root.appendChild(el("div", "empty-hint", "No representative identities are awaiting or deferring baseline review."));
      return;
    }
    rows.forEach(host => {
      const row = el("div", "baseline-row");
      const controls = el("span", "row-badge");
      const accept = el("button", "small-button", "ACCEPT");
      accept.style.minHeight = "25px";
      accept.addEventListener("click", () => updateBaseline(host.ip, "accepted"));
      controls.replaceChildren(accept);
      row.append(el("span", "row-time", host.baseline.toUpperCase()), el("span", "row-kind", host.name), el("span", "row-message", `${host.ip} · ${host.reasons.join("; ")}`), controls);
      root.appendChild(row);
    });
  }

  function renderTraps() {
    const root = $("#trapsPanel");
    root.replaceChildren();
    state.traps.forEach(trap => {
      const row = el("div", "trap-row");
      row.append(el("span", "row-time", `:${trap.port}`), el("span", "row-kind", trap.kind), el("span", "row-message", `${trap.hits} representative hit${trap.hits === 1 ? "" : "s"}. Deployment/stop require the self-hosted runtime.`), el("span", "row-badge", "VIEW ONLY"));
      root.appendChild(row);
    });
  }

  function renderReports() {
    const root = $("#reportsPanel");
    root.replaceChildren();
    if (!state.reports.length) {
      root.appendChild(el("div", "empty-hint", "No representative report preview has been generated in this page session."));
      return;
    }
    state.reports.forEach(report => {
      const row = el("div", "report-row");
      const open = el("button", "small-button", "OPEN");
      open.style.minHeight = "25px";
      open.addEventListener("click", () => openReport(report));
      const control = el("span", "row-badge");
      control.appendChild(open);
      row.append(el("span", "row-time", report.time), el("span", "row-kind", "REPORT"), el("span", "row-message", `${report.name} · session-only preview`), control);
      root.appendChild(row);
    });
  }

  function renderAudit() {
    const root = $("#auditPanel");
    root.replaceChildren();
    const hosts = visibleHosts();
    const elevated = hosts.filter(host => host.risk >= 50).length;
    const pending = hosts.filter(host => host.baseline !== "accepted").length;
    const metrics = el("div", "metric-grid");
    [["REP HOSTS", hosts.length], ["RISK >= 50", elevated], ["BASELINE REVIEW", pending], ["TRAPS VIEWED", state.traps.length], ["DIFF ADDED", state.diff.added.length], ["DIFF CHANGED", state.diff.changed.length]].forEach(([label, value]) => {
      const card = el("div", "metric-card");
      card.append(el("span", "", label), el("b", "", String(value)));
      metrics.appendChild(card);
    });
    root.appendChild(metrics);

    const diff = el("section", "detail-card");
    diff.appendChild(el("div", "section-title", "Representative observation diff"));
    const evidence = el("div", "evidence-list");
    [
      `Added: ${state.diff.added.length ? state.diff.added.join(", ") : "none"}`,
      `Removed: ${state.diff.removed.length ? state.diff.removed.join(", ") : "none"}`,
      `Changed: ${state.diff.changed.length ? state.diff.changed.join(", ") : "none"}`,
      "Read-only inspection does not advance observation state."
    ].forEach(text => evidence.appendChild(el("div", "evidence-item", text)));
    diff.appendChild(evidence);
    root.appendChild(diff);
  }

  function updateCounts() {
    $("#eventCount").textContent = String(state.events.length);
    $("#jobCount").textContent = String(state.jobs.length);
    $("#baselineCount").textContent = String(visibleHosts().filter(host => host.baseline !== "accepted").length);
  }

  function switchTab(name) {
    $$(".tab").forEach(tab => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    $$(".tab-panel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === name));
    if (name === "terminal") setTimeout(() => $("#terminalInput").focus(), 0);
  }

  function createRepresentativeReport() {
    const report = {
      id: Date.now(),
      time: nowTime(),
      name: `representative-report-${new Date().toISOString().replace(/[:.]/g, "-")}.html`
    };
    state.reports.unshift(report);
    addJob("HTML Report", "representative session", "Representative report preview generated in page memory; no file persisted." );
    addEvent("REPORT", `${report.name} generated as representative session preview; not persisted.`);
    renderReports();
    openReport(report);
  }

  function openReport(report) {
    const body = $("#reportBody");
    body.replaceChildren();
    body.appendChild(el("div", "report-watermark", "REPRESENTATIVE REPORT PREVIEW / NO LIVE LAN ACCESS / NOT PERSISTED"));
    body.appendChild(el("p", "action-note", `Generated ${report.time} from in-memory representative LANimals state for ${state.scope}.`));

    const summary = el("section", "report-section");
    summary.appendChild(el("h3", "", "Summary"));
    const metrics = el("div", "metric-grid");
    const hosts = visibleHosts();
    [["Hosts", hosts.length], ["Elevated", hosts.filter(h => h.risk >= 50).length], ["Pending baseline", hosts.filter(h => h.baseline !== "accepted").length]].forEach(([label, value]) => {
      const card = el("div", "metric-card");
      card.append(el("span", "", label), el("b", "", String(value)));
      metrics.appendChild(card);
    });
    summary.appendChild(metrics);
    body.appendChild(summary);

    const hostSection = el("section", "report-section");
    hostSection.appendChild(el("h3", "", "Representative inventory"));
    const table = el("table", "report-table");
    const head = document.createElement("thead");
    const hr = document.createElement("tr");
    ["Host", "IP", "Role", "Risk", "Baseline"].forEach(text => hr.appendChild(el("th", "", text)));
    head.appendChild(hr);
    const tbody = document.createElement("tbody");
    hosts.forEach(host => {
      const tr = document.createElement("tr");
      [host.name, host.ip, host.type, String(host.risk), host.baseline].forEach(text => tr.appendChild(el("td", "", text)));
      tbody.appendChild(tr);
    });
    table.append(head, tbody);
    hostSection.appendChild(table);
    body.appendChild(hostSection);

    $("#reportModal").classList.add("open");
    $("#reportModal").setAttribute("aria-hidden", "false");
    $("#closeReport").focus();
    switchTab("reports");
  }

  function closeReport() {
    $("#reportModal").classList.remove("open");
    $("#reportModal").setAttribute("aria-hidden", "true");
  }

  function toast(title, message) {
    const region = $("#toastRegion");
    const node = el("div", "toast");
    node.setAttribute("role", "status");
    node.append(el("strong", "", title), el("span", "", message));
    region.appendChild(node);
    setTimeout(() => node.remove(), 3800);
  }

  function appendTerminal(text, className = "") {
    const out = $("#terminalOutput");
    const line = el("div", className, text);
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  }

  function handleTerminal(commandText) {
    const command = commandText.trim();
    if (!command) return;
    appendTerminal(`lanimals> ${command}`, "prompt-line");
    const [verb] = command.toLowerCase().split(/\s+/);
    switch (verb) {
      case "help":
        appendTerminal("allowed: help status hosts events baseline traps audit discovery arp hostmap rogue rescore report clear");
        appendTerminal("self-hosted only: services cve inventory anomaly watchdog vt trap-deploy trap-stop", "rep");
        break;
      case "status":
        appendTerminal(`[REPRESENTATIVE] LANimals 2.1.0 · scope ${state.scope} · ${visibleHosts().length} session hosts · NO LIVE LAN ACCESS`, "rep");
        break;
      case "hosts":
        visibleHosts().forEach(host => appendTerminal(`${host.ip.padEnd(16)} ${host.name.padEnd(18)} risk=${String(host.risk).padStart(3)} baseline=${host.baseline}`));
        break;
      case "events":
        state.events.slice(0, 8).reverse().forEach(item => appendTerminal(`${item.time} ${item.kind.padEnd(10)} ${item.message}`));
        break;
      case "baseline":
        visibleHosts().filter(host => host.baseline !== "accepted").forEach(host => appendTerminal(`${host.ip} ${host.name} ${host.baseline}`));
        break;
      case "traps":
        state.traps.forEach(trap => appendTerminal(`:${trap.port} ${trap.kind} hits=${trap.hits} [REPRESENTATIVE VIEW ONLY]`, "rep"));
        break;
      case "audit":
        appendTerminal(`[REPRESENTATIVE] hosts=${visibleHosts().length} elevated=${visibleHosts().filter(h => h.risk >= 50).length} baseline_review=${visibleHosts().filter(h => h.baseline !== "accepted").length}`, "rep");
        switchTab("audit");
        break;
      case "discovery":
        runRepresentativeAction("discovery");
        appendTerminal(`[REPRESENTATIVE] discovery started for ${state.scope}; no network request issued.`, "rep");
        break;
      case "arp":
        runRepresentativeAction("arp");
        appendTerminal(`[REPRESENTATIVE] ARP refresh applied to session state; no ARP packets sent.`, "rep");
        break;
      case "hostmap":
        runRepresentativeAction("hostmap");
        appendTerminal(`[REPRESENTATIVE] topology rebuilt from page-session inventory.`, "rep");
        break;
      case "rogue":
        runRepresentativeAction("rogue");
        appendTerminal(`[REPRESENTATIVE] identity-change review refreshed.`, "rep");
        break;
      case "rescore":
        runRepresentativeAction("rescore");
        appendTerminal(`[REPRESENTATIVE] risk scores recomputed from session evidence.`, "rep");
        break;
      case "report":
        runRepresentativeAction("report");
        appendTerminal(`[REPRESENTATIVE] report preview created in memory; no file persisted.`, "rep");
        break;
      case "services":
      case "cve":
      case "inventory":
      case "anomaly":
      case "watchdog":
      case "vt":
      case "trap-deploy":
      case "trap-stop":
        appendTerminal(`UNAVAILABLE IN HOSTED MODE — ${verb} requires the self-hosted LANimals runtime.`, "rep");
        break;
      case "clear":
        $("#terminalOutput").replaceChildren();
        break;
      default:
        appendTerminal(`Command not in hosted representative allowlist: ${verb}`);
    }
  }

  function openPanel(which) {
    const ops = $("#operationsPanel");
    const host = $("#investigationPanel");
    const scrim = $("#mobileScrim");
    ops.classList.toggle("open", which === "ops");
    host.classList.toggle("open", which === "host");
    scrim.classList.add("open");
  }

  function closePanels() {
    $("#operationsPanel").classList.remove("open");
    $("#investigationPanel").classList.remove("open");
    $("#mobileScrim").classList.remove("open");
  }

  function bindEvents() {
    $$('[data-action]').forEach(button => {
      if (!button.disabled) button.addEventListener("click", () => runRepresentativeAction(button.dataset.action));
    });
    $$(".tab").forEach(tab => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));

    const search = $("#hostSearch");
    search.addEventListener("input", () => {
      state.filter = search.value;
      applyGraphFilter();
    });
    search.addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      const q = state.filter.trim().toLowerCase();
      const match = visibleHosts().find(host => `${host.name} ${host.ip} ${host.type}`.toLowerCase().includes(q));
      if (match) selectHost(match.ip, true);
    });

    $("#labelToggle").addEventListener("click", event => {
      state.showLabels = !state.showLabels;
      event.currentTarget.setAttribute("aria-pressed", String(state.showLabels));
      renderGraph();
    });

    $("#terminalForm").addEventListener("submit", event => {
      event.preventDefault();
      const input = $("#terminalInput");
      handleTerminal(input.value);
      input.value = "";
    });

    $("#opsToggle").addEventListener("click", () => openPanel("ops"));
    $("#hostToggle").addEventListener("click", () => openPanel("host"));
    $("#mobileScrim").addEventListener("click", closePanels);
    $("#closeReport").addEventListener("click", closeReport);
    $("#reportModal").addEventListener("click", event => {
      if (event.target === event.currentTarget) closeReport();
    });

    document.addEventListener("keydown", event => {
      if (event.key === "Escape") {
        closePanels();
        closeReport();
      }
    });
  }

  function seedEvents() {
    state.events = [
      { time: nowTime(-12), kind: "MODE", message: "Hosted representative workflow initialized; no API connection and no visitor-LAN access.", representative: true },
      { time: nowTime(-10), kind: "SCOPE", message: `Representative scope loaded: ${state.scope}.`, representative: true },
      { time: nowTime(-8), kind: "DISCOVERY", message: "Representative inventory hydrated with 9 session hosts.", representative: true },
      { time: nowTime(-6), kind: "BASELINE", message: "printer-01 identity change is awaiting explicit operator review.", representative: true },
      { time: nowTime(-4), kind: "RISK", message: "nas-01 has elevated representative risk with explainable service/CVE reasons.", representative: true },
      { time: nowTime(-2), kind: "TRAP", message: "Two representative trap records are available for read-only inspection.", representative: true }
    ];
  }

  function init() {
    seedEvents();
    bindEvents();
    renderGraph();
    renderHostDetail();
    renderEvidence();
    appendTerminal("LANimals representative command surface", "rep");
    appendTerminal("No live LAN access. Type 'help' for the hosted allowlist.", "rep");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
