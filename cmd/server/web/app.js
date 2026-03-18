async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

let uptimeTimer = null;
let currentConfigContainer = "";
let currentInstallProtocol = null;
let currentExportName = "";
let installInFlight = false;
let currentClientsProtocol = null;
let currentClientId = null;
let protocolByContainer = {};
const clientProtocolIds = ["wireguard", "awg", "awg2", "openvpn", "cloak", "shadowsocks", "ipsec", "socks5"];
let currentClientExports = null;
let currentClientName = "";

async function safeCopyText(text) {
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "-";
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts = [];
  if (days) parts.push(`${days}d`);
  parts.push(`${hours.toString().padStart(2, "0")}h`);
  parts.push(`${minutes.toString().padStart(2, "0")}m`);
  parts.push(`${seconds.toString().padStart(2, "0")}s`);
  return parts.join(" ");
}

function toMb(kbValue) {
  const num = Number(kbValue);
  if (!Number.isFinite(num)) return "";
  return Math.round(num / 1024);
}

function formatUptime(uptimeSec) {
  const secNum = Math.floor(Number(uptimeSec));
  if (!Number.isFinite(secNum) || secNum < 0) return "";
  const days = Math.floor(secNum / 86400);
  const hours = Math.floor((secNum % 86400) / 3600);
  const minutes = Math.floor((secNum % 3600) / 60);
  const seconds = secNum % 60;
  const hh = hours.toString().padStart(2, "0");
  const mm = minutes.toString().padStart(2, "0");
  const ss = seconds.toString().padStart(2, "0");
  return `${days}d ${hh}.${mm}.${ss}`;
}

function formatCpuLoadPercent(data) {
  if (data && data.cpu_load_perc) {
    return `${data.cpu_load_perc}%`;
  }
  const load1 = Number(data && data.load1);
  const cores = Number(data && data.cpu_cores);
  if (!Number.isFinite(load1) || !Number.isFinite(cores) || cores <= 0) return "";
  const perc = (load1 / cores) * 100;
  return `${Math.round(perc)}%`;
}

function updateUptime() {
  document.querySelectorAll("[data-started]").forEach((el) => {
    const started = el.dataset.started;
    if (!started) {
      el.textContent = "uptime: -";
      return;
    }
    const t = Date.parse(started);
    if (Number.isNaN(t)) {
      el.textContent = "uptime: -";
      return;
    }
    const diff = Date.now() - t;
    el.textContent = `uptime: ${formatDuration(diff)}`;
  });
}

function containerCard(c) {
  const el = document.createElement("div");
  el.className = "card";
  const stateClass = c.state === "running" ? "ok" : "bad";

  const configButton = c.config_path
    ? `<button class="btn config" data-action="config">config</button>`
    : "";
  const exportButton = c.config_path
    ? `<button class="btn export" data-action="export">export</button>`
    : "";
  const proto = protocolByContainer[c.names];
  const clientsButton = proto && clientProtocolIds.includes(proto.id)
    ? `<button class="btn clients" data-action="clients">clients</button>`
    : "";

  el.innerHTML = `
    <div class="inline">
      <h3>${c.names}</h3>
      <span class="pill ${stateClass}">${c.state}</span>
    </div>
    <div class="meta">${c.image}</div>
    <div class="meta">${c.status}</div>
    <div class="meta" data-started="${c.started_at || ""}">uptime: -</div>
    <div class="meta">${c.ports || "ports: -"}</div>
    <div class="meta">Connections: ${c.connections || "-"}</div>
    <div class="meta">CPU ${c.cpu_perc || "-"} · MEM ${c.mem_usage || "-"} (${c.mem_perc || "-"})</div>
    <div class="meta">NET ${c.net_io || "-"} · IO ${c.block_io || "-"} · PIDs ${c.pids || "-"}</div>
    <div class="buttons-row">
      <button class="btn restart" data-action="restart">Restart</button>
      <button class="btn start" data-action="start">Start</button>
      <button class="btn stop" data-action="stop">Stop</button>
      ${configButton}
      ${exportButton}
      ${clientsButton}
    </div>
  `;

  el.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.dataset.action;
      btn.disabled = true;
      try {
        if (action === "config") {
          await openConfig(c.names, c.config_path);
        } else if (action === "export") {
          await openExport(c.names);
        } else if (action === "clients") {
          if (proto) await openClients(proto);
        } else {
          await api(`/api/containers/${c.names}/${action}`, { method: "POST" });
          await loadContainers();
        }
      } catch (e) {
        alert(e.message);
      } finally {
        btn.disabled = false;
      }
    });
  });

  return el;
}

function protocolItem(p) {
  const el = document.createElement("div");
  el.className = "cascade-item";
  const stateClass = p.running ? "ok" : p.installed ? "bad" : "";
  const stateText = p.running ? "running" : p.installed ? "stopped" : "not installed";
  const actionLabel = p.installed ? "Remove" : "Install";
  const actionClass = p.installed ? "stop" : "start";

  el.innerHTML = `
    <div class="cascade-main">
      <div class="cascade-name">${p.name}</div>
      <div class="cascade-sub">${p.container}</div>
    </div>
    <div class="cascade-meta">
      <span class="pill ${stateClass}">${stateText}</span>
      <span class="meta">${p.ports || "ports: -"}</span>
      <button class="btn ${actionClass}" data-action="${p.installed ? "remove" : "install"}">${actionLabel}</button>
    </div>
  `;

  const actionBtn = el.querySelector("button");
  actionBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    if (p.installed) {
      await removeProtocol(p);
    } else {
      await openInstall(p);
    }
  });

  return el;
}

function protocolGroup(title, items) {
  const details = document.createElement("details");
  details.className = "cascade-group";
  details.open = false;
  const summary = document.createElement("summary");
  summary.textContent = title;
  const children = document.createElement("div");
  children.className = "cascade-children";
  items.forEach((p) => children.appendChild(protocolItem(p)));
  details.appendChild(summary);
  details.appendChild(children);
  return details;
}

function protocolSection(title, blocks) {
  const section = document.createElement("div");
  section.className = "cascade-section";
  const header = document.createElement("div");
  header.className = "cascade-title";
  header.textContent = title;
  section.appendChild(header);
  blocks.forEach((b) => section.appendChild(b));
  return section;
}

async function loadHealth() {
  const pill = document.getElementById("health");
  try {
    const data = await api("/api/health");
    if (data.docker_ok) {
      pill.className = "pill ok";
      pill.textContent = data.docker_version;
    } else {
      pill.className = "pill bad";
      pill.textContent = "docker error";
    }
  } catch (e) {
    pill.className = "pill bad";
    pill.textContent = "error";
  }
}

async function loadMonitoring() {
  const wrap = document.getElementById("monitoringHeader");
  try {
    const data = await api("/api/monitoring");
    const uptime = formatUptime(data.uptime_sec);
    const totalMb = toMb(data.mem_total_kb);
    const usedMb = toMb(data.mem_used_kb);
    const cpuPerc = formatCpuLoadPercent(data);
    const cards = [
      { key: "load", label: "Load", value: cpuPerc || "-" },
      { key: "uptime", label: "Uptime", value: uptime || "-" },
      { key: "memUsed", label: "Mem Used", value: `${usedMb || "-"} / ${totalMb || "-"} MB` },
      { key: "memTotal", label: "Mem Total", value: `${totalMb || "-"} MB` },
    ];
    if (!wrap.dataset.ready) {
      wrap.innerHTML = "";
      cards.forEach((c) => {
        const el = document.createElement("div");
        el.className = "monitoring-item";
        el.dataset.key = c.key;
        el.innerHTML = `<div class="monitoring-label">${c.label}</div><div class="monitoring-value">${c.value}</div>`;
        wrap.appendChild(el);
      });
      wrap.dataset.ready = "1";
    } else {
      cards.forEach((c) => {
        const el = wrap.querySelector(`[data-key="${c.key}"]`);
        if (!el) return;
        const valueEl = el.querySelector(".monitoring-value");
        if (valueEl) valueEl.textContent = c.value;
      });
    }
  } catch (e) {
    wrap.innerHTML = `<div class="monitoring-item"><div class="monitoring-label">monitoring</div><div class="monitoring-value">error</div></div>`;
    delete wrap.dataset.ready;
  }
}

async function loadProtocols() {
  const list = document.getElementById("protocols");
  list.innerHTML = "";
  const protocols = await api("/api/protocols");
  const byId = new Map(protocols.map((p) => [p.id, p]));
  protocolByContainer = {};
  protocols.forEach((p) => {
    if (p.container) protocolByContainer[p.container] = p;
  });

  const wireguardGroup = [
    byId.get("wireguard"),
    byId.get("awg"),
    byId.get("awg2"),
  ].filter(Boolean);

  const openvpnGroup = [
    byId.get("openvpn"),
    byId.get("cloak"),
    byId.get("shadowsocks"),
  ].filter(Boolean);

  const protocolsBlocks = [];
  if (wireguardGroup.length) protocolsBlocks.push(protocolGroup("WireGuard", wireguardGroup));
  if (openvpnGroup.length) protocolsBlocks.push(protocolGroup("OpenVPN", openvpnGroup));

  const otherProtocols = [
    byId.get("xray"),
    byId.get("ipsec"),
  ].filter(Boolean);
  otherProtocols.forEach((p) => protocolsBlocks.push(protocolGroup(p.name, [p])));

  const servicesItems = [
    byId.get("socks5"),
    byId.get("dns"),
    byId.get("sftp"),
  ].filter(Boolean);

  list.appendChild(protocolSection("Протоколы", protocolsBlocks));
  list.appendChild(protocolSection("Сервисы", servicesItems.map((p) => protocolGroup(p.name, [p]))));
}

async function loadPorts() {
  const wrap = document.getElementById("portsList");
  if (!wrap) return;
  wrap.textContent = "Загрузка...";
  try {
    const data = await api("/api/ports");
    if (!Array.isArray(data) || data.length === 0) {
      wrap.innerHTML = `<div class="ports-empty">Свободно</div>`;
      return;
    }
    data.sort((a, b) => {
      const pa = Number(a.port) || 0;
      const pb = Number(b.port) || 0;
      if (pa !== pb) return pa - pb;
      return String(a.proto).localeCompare(String(b.proto));
    });
    wrap.innerHTML = "";
    data.forEach((item) => {
      const row = document.createElement("div");
      row.className = "ports-row";
      const service = item.service || item.container || "-";
      row.innerHTML = `<div class="ports-port">${item.port}/${item.proto}</div><div class="ports-service">${service}</div>`;
      wrap.appendChild(row);
    });
  } catch (e) {
    wrap.textContent = "ошибка";
  }
}

function parseLines(value) {
  return (value || "")
    .split("\n")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

async function loadSplitTunnel() {
  const modeEl = document.getElementById("splitMode");
  const domainsEl = document.getElementById("splitDomains");
  const subnetsEl = document.getElementById("splitSubnets");
  const statusEl = document.getElementById("splitStatus");
  if (!modeEl || !domainsEl || !subnetsEl || !statusEl) return;
  try {
    const data = await api("/api/split-tunnel");
    modeEl.value = data.mode || "exclude";
    domainsEl.value = Array.isArray(data.domains) ? data.domains.join("\n") : "";
    subnetsEl.value = Array.isArray(data.subnets) ? data.subnets.join("\n") : "";
    if (data.updated_at) {
      statusEl.textContent = `Обновлено: ${new Date(data.updated_at).toLocaleString()}`;
    } else {
      statusEl.textContent = "";
    }
  } catch (e) {
    statusEl.textContent = e.message;
  }
}

async function saveSplitTunnel(applyNow) {
  const modeEl = document.getElementById("splitMode");
  const domainsEl = document.getElementById("splitDomains");
  const subnetsEl = document.getElementById("splitSubnets");
  const statusEl = document.getElementById("splitStatus");
  const saveBtn = document.getElementById("splitSave");
  const applyBtn = document.getElementById("splitApply");
  if (!modeEl || !domainsEl || !subnetsEl || !statusEl || !saveBtn || !applyBtn) return;
  saveBtn.disabled = true;
  applyBtn.disabled = true;
  statusEl.textContent = applyNow ? "Применяю..." : "Сохраняю...";
  try {
    const payload = {
      mode: modeEl.value,
      domains: parseLines(domainsEl.value),
      subnets: parseLines(subnetsEl.value),
      apply: Boolean(applyNow),
    };
    const data = await api("/api/split-tunnel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (data.updated_at) {
      statusEl.textContent = applyNow ? "Сохранено, применение запущено." : "Сохранено.";
    } else {
      statusEl.textContent = applyNow ? "Применение запущено." : "Сохранено.";
    }
  } catch (e) {
    statusEl.textContent = e.message;
  } finally {
    saveBtn.disabled = false;
    applyBtn.disabled = false;
  }
}

async function loadContainers() {
  const list = document.getElementById("containers");
  const select = document.getElementById("logContainer");
  list.innerHTML = "";
  select.innerHTML = "";
  const containers = await api("/api/containers");
  containers.forEach((c) => {
    list.appendChild(containerCard(c));
    const opt = document.createElement("option");
    opt.value = c.names;
    opt.textContent = c.names;
    select.appendChild(opt);
  });

  updateUptime();
  if (uptimeTimer) {
    clearInterval(uptimeTimer);
  }
  uptimeTimer = setInterval(updateUptime, 1000);
}

async function loadAlerts() {
  const wrap = document.getElementById("alerts");
  if (!wrap) return;
  try {
    const data = await api("/api/alerts");
    if (!Array.isArray(data) || data.length === 0) {
      wrap.innerHTML = "";
      return;
    }
    wrap.innerHTML = "";
    data.forEach((a) => {
      const el = document.createElement("div");
      el.className = `alert-item ${a.level || ""}`;
      el.textContent = a.message || "Alert";
      wrap.appendChild(el);
    });
  } catch (e) {
    wrap.innerHTML = "";
  }
}

async function loadLogs() {
  const name = document.getElementById("logContainer").value;
  const out = document.getElementById("logs");
  if (!name) {
    out.textContent = "Нет контейнера";
    return;
  }
  out.textContent = "Загрузка...";
  try {
    const data = await api(`/api/containers/${name}/logs?tail=200`);
    out.textContent = data.logs || "(пусто)";
  } catch (e) {
    out.textContent = e.message;
  }
}

function createConfigRow(line, idx) {
  const row = document.createElement("div");
  row.className = "config-row";
  const index = document.createElement("div");
  index.className = "config-idx";
  index.textContent = String(idx + 1).padStart(2, "0");
  const input = document.createElement("input");
  input.value = line;
  row.appendChild(index);
  row.appendChild(input);
  return row;
}

async function openConfig(name, path) {
  const modal = document.getElementById("configModal");
  const title = document.getElementById("configTitle");
  const pathEl = document.getElementById("configPath");
  const linesEl = document.getElementById("configLines");

  currentConfigContainer = name;
  title.textContent = `Конфиг: ${name}`;
  pathEl.textContent = path || "";
  linesEl.innerHTML = "";

  const data = await api(`/api/containers/${name}/config`);
  pathEl.textContent = data.path || path || "";

  const lines = (data.content || "").replace(/\r/g, "").split("\n");
  lines.forEach((line, idx) => {
    linesEl.appendChild(createConfigRow(line, idx));
  });

  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeConfig() {
  const modal = document.getElementById("configModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  currentConfigContainer = "";
}

async function saveConfig() {
  if (!currentConfigContainer) return;
  const linesEl = document.getElementById("configLines");
  const inputs = Array.from(linesEl.querySelectorAll("input"));
  const content = inputs.map((i) => i.value).join("\n");
  await api(`/api/containers/${currentConfigContainer}/config`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  closeConfig();
}

function addLine() {
  const linesEl = document.getElementById("configLines");
  const idx = linesEl.querySelectorAll(".config-row").length;
  linesEl.appendChild(createConfigRow("", idx));
}

async function openInstall(protocol) {
  currentInstallProtocol = protocol;
  const modal = document.getElementById("installModal");
  const title = document.getElementById("installTitle");
  const sub = document.getElementById("installSub");
  const fieldsEl = document.getElementById("installFields");
  const statusEl = document.getElementById("installStatus");

  title.textContent = `Установка: ${protocol.name}`;
  sub.textContent = protocol.container;
  fieldsEl.innerHTML = "";
  statusEl.textContent = "";
  installInFlight = false;
  const installBtn = document.getElementById("installGo");
  const closeBtn = document.getElementById("closeInstall");
  installBtn.disabled = false;
  installBtn.textContent = "Установить";
  closeBtn.disabled = false;

  (protocol.fields || []).forEach((f) => {
    const row = document.createElement("div");
    row.className = "config-row";
    const label = document.createElement("div");
    label.className = "config-idx";
    label.textContent = f.label || f.key;

    let input;
    if (f.type === "select") {
      input = document.createElement("select");
      (f.options || []).forEach((opt) => {
        const o = document.createElement("option");
        o.value = opt;
        o.textContent = opt;
        if (opt === f.default) o.selected = true;
        input.appendChild(o);
      });
    } else {
      input = document.createElement("input");
      input.type = f.type === "password" ? "password" : "text";
      if (f.type === "number") input.inputMode = "numeric";
      input.value = f.default || "";
      if (f.placeholder) input.placeholder = f.placeholder;
    }
    input.dataset.key = f.key;
    input.dataset.required = f.required ? "1" : "0";

    row.appendChild(label);
    row.appendChild(input);
    fieldsEl.appendChild(row);
  });

  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeInstall() {
  const modal = document.getElementById("installModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  currentInstallProtocol = null;
  installInFlight = false;
}

async function doInstall() {
  if (!currentInstallProtocol || installInFlight) return;
  installInFlight = true;
  const statusEl = document.getElementById("installStatus");
  const installBtn = document.getElementById("installGo");
  const closeBtn = document.getElementById("closeInstall");
  const fieldsEl = document.getElementById("installFields");
  installBtn.disabled = true;
  closeBtn.disabled = true;
  installBtn.textContent = "Установка...";
  statusEl.textContent = "Запускаю установку, это может занять несколько минут.";
  fieldsEl.querySelectorAll("input, select").forEach((el) => (el.disabled = true));

  const inputs = Array.from(fieldsEl.querySelectorAll("input, select"));
  const options = {};
  for (const input of inputs) {
    const key = input.dataset.key;
    const val = input.value.trim();
    const required = input.dataset.required === "1";
    if (required && !val) {
      alert(`Поле ${key} обязательно`);
      installInFlight = false;
      installBtn.disabled = false;
      closeBtn.disabled = false;
      installBtn.textContent = "Установить";
      fieldsEl.querySelectorAll("input, select").forEach((el) => (el.disabled = false));
      statusEl.textContent = "Заполните обязательные поля.";
      return;
    }
    options[key] = val;
  }

  try {
    await api(`/api/protocols/${currentInstallProtocol.id}/install`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ options }),
    });
    statusEl.textContent = "Установка завершена.";
    closeInstall();
    await loadProtocols();
    await loadContainers();
  } catch (e) {
    statusEl.textContent = `Ошибка: ${e.message}`;
  } finally {
    installInFlight = false;
    installBtn.disabled = false;
    closeBtn.disabled = false;
    installBtn.textContent = "Установить";
    fieldsEl.querySelectorAll("input, select").forEach((el) => (el.disabled = false));
  }
}

async function removeProtocol(p) {
  if (!confirm(`Удалить ${p.name}?`)) return;
  await api(`/api/protocols/${p.id}/remove`, { method: "POST" });
  await loadProtocols();
  await loadContainers();
}

async function openExport(name) {
  const modal = document.getElementById("exportModal");
  const title = document.getElementById("exportTitle");
  const pathEl = document.getElementById("exportPath");
  const contentEl = document.getElementById("exportContent");

  title.textContent = `Экспорт: ${name}`;
  pathEl.textContent = "";
  contentEl.textContent = "Загрузка...";

  const data = await api(`/api/containers/${name}/export`);
  pathEl.textContent = data.path || "";
  contentEl.textContent = data.content || "";
  currentExportName = name;

  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeExport() {
  const modal = document.getElementById("exportModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  currentExportName = "";
}

function downloadExport() {
  const content = document.getElementById("exportContent").textContent || "";
  const name = currentExportName || "config";
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name}.conf`;
  a.click();
  URL.revokeObjectURL(url);
}

async function copyExport() {
  const content = document.getElementById("exportContent").textContent || "";
  if (!content) return;
  await safeCopyText(content);
}

async function openClients(protocol) {
  currentClientsProtocol = protocol;
  const modal = document.getElementById("clientsModal");
  document.getElementById("clientsTitle").textContent = `Клиенты: ${protocol.name}`;
  document.getElementById("clientsSub").textContent = protocol.container;
  document.getElementById("clientName").value = "";
  const addBtn = document.getElementById("addClient");
  const supported = ["wireguard", "awg", "awg2", "socks5"].includes(protocol.id);
  addBtn.disabled = !supported;
  document.getElementById("clientName").disabled = !supported;
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  await loadClients();
}

function closeClients() {
  const modal = document.getElementById("clientsModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  currentClientsProtocol = null;
}

async function loadClients() {
  const list = document.getElementById("clientsList");
  if (!currentClientsProtocol) return;
  list.textContent = "Загрузка...";
  try {
    const data = await api(`/api/clients?protocol=${currentClientsProtocol.id}`);
    if (!Array.isArray(data) || data.length === 0) {
      list.textContent = "Нет клиентов";
      return;
    }
    list.innerHTML = "";
    const showTelegram = currentClientsProtocol.id === "socks5";
    data.forEach((c) => {
      const row = document.createElement("div");
      row.className = "client-row";
      const meta = c.address ? `IP ${c.address}` : "";
      row.innerHTML = `
        <div>
          <div class="client-name">${c.name}</div>
          <div class="client-meta">${meta}</div>
        </div>
        <div class="client-actions">
          <button class="btn export" data-id="${c.id}">Export</button>
          ${showTelegram ? `<button class="btn secondary telegram" data-id="${c.id}">Telegram</button>` : ""}
          <button class="btn stop" data-id="${c.id}">Delete</button>
        </div>
      `;
      row.querySelector(".btn.export").addEventListener("click", async (e) => {
        e.stopPropagation();
        await openClientExport(c.id, c.name);
      });
      const tgBtn = row.querySelector(".btn.telegram");
      if (tgBtn) {
        tgBtn.addEventListener("click", async (e) => {
          e.stopPropagation();
          await copyTelegramForClient(c.id);
        });
      }
      row.querySelector(".btn.stop").addEventListener("click", async (e) => {
        e.stopPropagation();
        await deleteClient(c.id, c.name);
      });
      list.appendChild(row);
    });
  } catch (e) {
    list.textContent = e.message;
  }
}

async function addClient() {
  if (!currentClientsProtocol) return;
  const name = document.getElementById("clientName").value.trim();
  const addBtn = document.getElementById("addClient");
  addBtn.disabled = true;
  try {
    await api("/api/clients", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ protocol_id: currentClientsProtocol.id, name }),
    });
    document.getElementById("clientName").value = "";
    await loadClients();
  } catch (e) {
    alert(e.message);
  } finally {
    addBtn.disabled = false;
  }
}

async function openClientExport(id, name) {
  currentClientId = id;
  currentClientName = name || "client";
  const modal = document.getElementById("clientExportModal");
  document.getElementById("clientExportTitle").textContent = `Экспорт: ${name}`;
  document.getElementById("clientExportSub").textContent = "";
  const downloadBtn = document.getElementById("clientExportDownload");
  const copyBtn = document.getElementById("clientExportCopy");
  const qrBtn = document.getElementById("clientExportQr");
  const tgBtn = document.getElementById("clientExportTelegram");
  const tgBox = document.getElementById("clientTelegram");
  downloadBtn.disabled = true;
  copyBtn.disabled = true;
  qrBtn.disabled = true;
  tgBtn.disabled = true;
  tgBtn.style.display = "none";
  tgBox.textContent = "";
  currentClientExports = null;

  try {
    const data = await api(`/api/clients/${id}/export`);
    currentClientExports = data || {};
    downloadBtn.disabled = !currentClientExports.vpn;
    copyBtn.disabled = !currentClientExports.config;
    const hasQr = (Array.isArray(currentClientExports.qr_pngs) && currentClientExports.qr_pngs.length) ||
      currentClientExports.qr_png ||
      currentClientExports.qr_png_long ||
      currentClientExports.qr_png_short;
    qrBtn.disabled = !hasQr;
    const allowTelegram = currentClientsProtocol && currentClientsProtocol.id === "socks5";
    if (allowTelegram) {
      tgBtn.style.display = "inline-flex";
      if (currentClientExports.telegram) {
        tgBtn.disabled = false;
        tgBox.textContent = currentClientExports.telegram;
      }
    }
  } catch (e) {
    alert(e.message);
  }

  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeClientExport() {
  const modal = document.getElementById("clientExportModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  currentClientId = null;
  currentClientExports = null;
  currentClientName = "";
}

async function deleteClient(id, name) {
  if (!confirm(`Удалить клиента ${name}?`)) return;
  await api(`/api/clients/${id}`, { method: "DELETE" });
  await loadClients();
}

function downloadClientExport() {
  if (!currentClientExports || !currentClientExports.vpn) return;
  const content = currentClientExports.vpn;
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safe = (currentClientName || "client").replace(/[^a-z0-9-_]+/gi, "_");
  a.download = `${safe}.vpn`;
  a.click();
  URL.revokeObjectURL(url);
}

async function copyClientConfig() {
  if (!currentClientExports || !currentClientExports.config) return;
  await safeCopyText(currentClientExports.config);
}

async function copyTelegramLink() {
  if (!currentClientExports || !currentClientExports.telegram) return;
  await safeCopyText(currentClientExports.telegram);
}

async function copyTelegramForClient(id) {
  try {
    const data = await api(`/api/clients/${id}/export`);
    if (!data.telegram) {
      alert("Telegram ссылка недоступна для этого клиента.");
      return;
    }
    await safeCopyText(data.telegram);
  } catch (e) {
    alert(e.message);
  }
}

function openQrModal() {
  const modal = document.getElementById("qrModal");
  const grid = document.getElementById("qrGrid");
  if (!currentClientExports || !grid) return;

  let items = [];
  if (Array.isArray(currentClientExports.qr_pngs) && currentClientExports.qr_pngs.length) {
    items = currentClientExports.qr_pngs.slice();
  } else if (currentClientExports.qr_png_long || currentClientExports.qr_png_short) {
    if (currentClientExports.qr_png_long) items.push(currentClientExports.qr_png_long);
    if (currentClientExports.qr_png_short) items.push(currentClientExports.qr_png_short);
  } else if (currentClientExports.qr_png) {
    items = [currentClientExports.qr_png];
  }

  grid.innerHTML = "";
  if (!items.length) {
    grid.textContent = "—";
  } else {
    items.forEach((png, idx) => {
      const card = document.createElement("div");
      card.className = "qr-card";
      const label = document.createElement("div");
      label.className = "export-label";
      label.textContent = `QR ${idx + 1}/${items.length}`;
      const box = document.createElement("div");
      box.className = "qr-box";
      box.innerHTML = `<img src=\"data:image/png;base64,${png}\" alt=\"QR ${idx + 1}\" />`;
      card.appendChild(label);
      card.appendChild(box);
      grid.appendChild(card);
    });
  }
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeQrModal() {
  const modal = document.getElementById("qrModal");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
}

async function init() {
  await loadHealth();
  await loadMonitoring();
  await loadProtocols();
  await loadPorts();
  await loadSplitTunnel();
  await loadAlerts();
  await loadContainers();

  document.getElementById("loadLogs").addEventListener("click", loadLogs);
  document.getElementById("closeConfig").addEventListener("click", closeConfig);
  document.getElementById("saveConfig").addEventListener("click", saveConfig);
  document.getElementById("addLine").addEventListener("click", addLine);

  document.getElementById("closeInstall").addEventListener("click", closeInstall);
  document.getElementById("installGo").addEventListener("click", doInstall);

  document.getElementById("closeExport").addEventListener("click", closeExport);
  document.getElementById("downloadExport").addEventListener("click", downloadExport);
  document.getElementById("copyExport").addEventListener("click", copyExport);
  document.getElementById("closeClients").addEventListener("click", closeClients);
  document.getElementById("addClient").addEventListener("click", addClient);
  document.getElementById("closeClientExport").addEventListener("click", closeClientExport);
  document.getElementById("clientExportDownload").addEventListener("click", downloadClientExport);
  document.getElementById("clientExportCopy").addEventListener("click", copyClientConfig);
  document.getElementById("clientExportTelegram").addEventListener("click", copyTelegramLink);
  document.getElementById("clientExportQr").addEventListener("click", openQrModal);
  document.getElementById("closeQr").addEventListener("click", closeQrModal);
  const splitSave = document.getElementById("splitSave");
  const splitApply = document.getElementById("splitApply");
  if (splitSave && splitApply) {
    splitSave.addEventListener("click", () => saveSplitTunnel(false));
    splitApply.addEventListener("click", () => saveSplitTunnel(true));
  }
  const restartBtn = document.getElementById("restartServer");
  if (restartBtn) {
    restartBtn.addEventListener("click", async () => {
      if (!confirm("Перезагрузить сервер? Это оборвет все соединения.")) return;
      restartBtn.disabled = true;
      restartBtn.textContent = "Перезагрузка...";
      try {
        await api("/api/server/restart", { method: "POST" });
      } catch (e) {
        alert(e.message);
        restartBtn.disabled = false;
        restartBtn.textContent = "Перезапустить сервер";
      }
    });
  }

  document.getElementById("configModal").addEventListener("click", (e) => {
    if (e.target.id === "configModal") closeConfig();
  });
  document.getElementById("installModal").addEventListener("click", (e) => {
    if (e.target.id === "installModal" && !installInFlight) closeInstall();
  });
  document.getElementById("exportModal").addEventListener("click", (e) => {
    if (e.target.id === "exportModal") closeExport();
  });
  document.getElementById("clientsModal").addEventListener("click", (e) => {
    if (e.target.id === "clientsModal") closeClients();
  });
  document.getElementById("clientExportModal").addEventListener("click", (e) => {
    if (e.target.id === "clientExportModal") closeClientExport();
  });
  document.getElementById("qrModal").addEventListener("click", (e) => {
    if (e.target.id === "qrModal") closeQrModal();
  });

  setInterval(loadHealth, 30000);
  setInterval(loadMonitoring, 15000);
  setInterval(loadPorts, 600000);
  setInterval(loadAlerts, 20000);
}

init().catch((e) => {
  console.error(e);
});
