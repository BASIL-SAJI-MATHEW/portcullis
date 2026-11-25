"use strict";
// Every value that comes from the server is written with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
let token = sessionStorage.getItem("portcullis_token") || "";
let timer = null;

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method: options.method || "GET", headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (res.status === 401) { askForToken(); throw new Error("A token is required"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
  return data;
}

function askForToken() {
  const dialog = $("auth");
  if (!dialog.open) dialog.showModal();
}

function toast(message) {
  const box = $("error");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { box.hidden = true; }, 5000);
}

function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
function fmtExpiry(ts) { return ts ? new Date(ts * 1000).toLocaleString() : "never"; }

function renderChart(hourly) {
  const box = $("chart");
  box.replaceChildren();
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 480 120");
  svg.setAttribute("preserveAspectRatio", "none");
  const defs = document.createElementNS(SVG, "defs");
  const grad = document.createElementNS(SVG, "linearGradient");
  grad.setAttribute("id", "bar"); grad.setAttribute("x1", "0"); grad.setAttribute("y1", "0");
  grad.setAttribute("x2", "0"); grad.setAttribute("y2", "1");
  for (const [offset, color] of [["0", "#38bdf8"], ["1", "#7c3aed"]]) {
    const stop = document.createElementNS(SVG, "stop");
    stop.setAttribute("offset", offset); stop.setAttribute("stop-color", color);
    grad.appendChild(stop);
  }
  defs.appendChild(grad); svg.appendChild(defs);
  const peak = Math.max(1, ...hourly.map((h) => h.failures));
  hourly.forEach((h, i) => {
    const height = Math.max(h.failures ? 3 : 1, (h.failures / peak) * 112);
    const rect = document.createElementNS(SVG, "rect");
    rect.setAttribute("x", String(i * 20 + 2)); rect.setAttribute("width", "16");
    rect.setAttribute("y", String(118 - height)); rect.setAttribute("height", String(height));
    rect.setAttribute("rx", "3");
    const tip = document.createElementNS(SVG, "title");
    tip.textContent = h.failures + " failed logins, " + new Date(h.hour_start * 1000).getHours() + ":00";
    rect.appendChild(tip);
    svg.appendChild(rect);
  });
  box.appendChild(svg);
}

function renderRank(id, rows) {
  const list = $(id);
  list.replaceChildren();
  if (!rows.length) list.appendChild(el("li", "No data yet"));
  for (const row of rows) {
    const li = el("li");
    li.append(el("span", row.name, "mono"), el("span", row.count, "n"));
    list.appendChild(li);
  }
}

function renderBans(bans) {
  const body = $("bans");
  body.replaceChildren();
  $("bans-empty").hidden = bans.length > 0;
  const more = $("bans-more");
  more.hidden = bans.length <= 50;
  more.textContent = "Showing the newest 50 of " + bans.length + " blocks. Use the command line to see all of them.";
  for (const ban of bans.slice(0, 50)) {
    const tr = el("tr");
    const button = el("button", "Unblock", "ghost");
    button.addEventListener("click", () => act("/api/unban", { ip: ban.ip }));
    const last = el("td"); last.appendChild(button);
    tr.append(el("td", ban.ip, "mono"), el("td", ban.reason), el("td", ban.source),
              el("td", fmtExpiry(ban.expires)), last);
    body.appendChild(tr);
  }
}

function renderEvents(events) {
  const body = $("events");
  body.replaceChildren();
  for (const ev of events.slice(0, 40)) {
    const tr = el("tr");
    tr.append(el("td", fmtTime(ev.ts)), el("td", ev.ip, "mono"), el("td", ev.user),
              el("td", ev.service.toUpperCase()),
              el("td", ev.success ? "login ok" : "failed", ev.success ? "ok" : "bad"));
    body.appendChild(tr);
  }
}

function renderAllowed(map) {
  const list = $("allowed");
  list.replaceChildren();
  const entries = Object.entries(map);
  if (!entries.length) list.appendChild(el("li", "Only private addresses and your config allow list are protected."));
  for (const [ip, note] of entries) {
    const li = el("li");
    const remove = el("button", "Remove", "ghost");
    remove.addEventListener("click", () => act("/api/unallow", { ip }));
    li.append(el("span", note ? ip + " (" + note + ")" : ip, "mono"), remove);
    list.appendChild(li);
  }
}

async function refresh() {
  try {
    const [summary, bans, events] = await Promise.all([
      api("/api/summary"), api("/api/bans"), api("/api/events?limit=40")]);
    const s = summary.stats;
    $("c-bans").textContent = s.active_bans;
    $("c-fails").textContent = s.failures_24h;
    $("c-attackers").textContent = s.unique_attackers_24h;
    $("c-wins").textContent = s.successes_24h;
    const mode = $("mode");
    mode.textContent = summary.mode === "enforce" ? "Blocking on" : "Observe mode";
    mode.className = "badge " + summary.mode;
    mode.title = summary.mode === "enforce" ? "Attackers are blocked in the firewall."
      : "Nothing is blocked. Portcullis only reports what it would block.";
    $("version").textContent = "v" + summary.version;
    renderChart(s.hourly); renderRank("top-ips", s.top_ips); renderRank("top-users", s.top_users);
    renderBans(bans.bans); renderEvents(events.events); renderAllowed(summary.allowed);
    const status = $("status"); status.textContent = "live"; status.className = "status live";
  } catch (err) {
    const status = $("status"); status.textContent = "offline"; status.className = "status down";
    if (!String(err.message).includes("token")) console.warn(err);
  }
}

async function act(path, body) {
  try { await api(path, { method: "POST", body }); await refresh(); }
  catch (err) { toast(err.message); }
}

$("ban-form").addEventListener("submit", (e) => {
  e.preventDefault();
  act("/api/ban", { ip: $("ban-ip").value.trim(), hours: Number($("ban-hours").value) });
  $("ban-ip").value = "";
});
$("allow-form").addEventListener("submit", (e) => {
  e.preventDefault();
  act("/api/allow", { ip: $("allow-ip").value.trim(), note: $("allow-note").value.trim() });
  $("allow-ip").value = ""; $("allow-note").value = "";
});
$("auth-form").addEventListener("submit", () => {
  token = $("auth-token").value.trim();
  sessionStorage.setItem("portcullis_token", token);
  refresh();
});

refresh();
timer = setInterval(refresh, 3000);
document.addEventListener("visibilitychange", () => {
  clearInterval(timer);
  if (!document.hidden) { refresh(); timer = setInterval(refresh, 3000); }
});
