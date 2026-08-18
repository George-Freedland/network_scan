#!/usr/bin/env python3
"""Local web-dashboard GUI for network_inventory.

Starts a small HTTP server bound to localhost and opens a modern dashboard in
your browser. It reuses network_inventory.py for all data collection, so the
standalone CLI still works on its own. Standard library only — no dependencies.

    python3 network_inventory_gui.py
    python3 network_inventory_gui.py --port 8765 --no-open

The server is bound to 127.0.0.1 (not reachable from the network) and does not
send Access-Control-Allow-Origin, so other websites cannot read the results.
Only run this on networks you own or are authorized to inspect.
"""

from __future__ import annotations

import argparse
import io
import json
import secrets
import threading
import time
import webbrowser
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

import network_inventory as ni

TOKEN = secrets.token_urlsafe(16)

# Progress log shared with the browser while a scan runs.
_progress: list[str] = []
_progress_lock = threading.Lock()
_scan_lock = threading.Lock()
_last_report: dict[str, Any] | None = None


class _ProgressWriter(io.TextIOBase):
    """Capture build_report's stdout lines into the progress buffer."""

    def write(self, s: str) -> int:
        for line in s.splitlines():
            line = _strip_ansi(line).strip()
            if line:
                with _progress_lock:
                    _progress.append(line)
        return len(s)


def _strip_ansi(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\033":
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def run_scan(params: dict[str, list[str]]) -> dict[str, Any]:
    def flag(name: str) -> bool:
        return params.get(name, ["0"])[0] in ("1", "true", "on", "yes")

    args = SimpleNamespace(
        json=False,
        output=None,
        fast=flag("fast"),
        no_probe=flag("no_probe"),
        offline=flag("offline"),
        no_bluetooth=flag("no_bluetooth"),
        subnet=(params.get("subnet", [""])[0] or None),
        mdns_seconds=float(params.get("mdns_seconds", ["3.0"])[0]),
        probe_timeout=float(params.get("probe_timeout", ["0.45"])[0]),
        no_color=True,
    )
    ni.IS_TTY = False
    with _progress_lock:
        _progress.clear()
    writer = _ProgressWriter()
    with redirect_stdout(writer):
        report, *_ = ni.build_report(args)
    with _progress_lock:
        _progress.append("Done.")
    return report


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # quiet
        pass

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._send(200, INDEX_HTML.replace("__TOKEN__", TOKEN).encode(), "text/html; charset=utf-8")
            return

        if params.get("token", [""])[0] != TOKEN:
            self._send(403, b'{"error":"bad token"}', "application/json")
            return

        if path == "/api/progress":
            with _progress_lock:
                data = {"lines": list(_progress)}
            self._send(200, json.dumps(data).encode(), "application/json")
            return

        if path == "/api/scan":
            global _last_report
            if not _scan_lock.acquire(blocking=False):
                self._send(429, b'{"error":"a scan is already running"}', "application/json")
                return
            try:
                report = run_scan(params)
                _last_report = report
                body = json.dumps(report, default=str).encode()
                self._send(200, body, "application/json")
            except Exception as exc:  # surface errors to the UI
                self._send(500, json.dumps({"error": str(exc)}).encode(), "application/json")
            finally:
                _scan_lock.release()
            return

        self._send(404, b'{"error":"not found"}', "application/json")


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Inventory</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#131a26; --panel2:#0f1622; --line:#223047;
    --txt:#e6edf6; --dim:#8aa0bd; --accent:#4da3ff; --green:#3fb950;
    --yellow:#e3b341; --red:#f85149; --chip:#1c2740;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line);
    display:flex; align-items:center; gap:20px; flex-wrap:wrap;
    background:linear-gradient(180deg,#0f1826,#0b0f17); position:sticky; top:0; z-index:5; }
  h1 { font-size:18px; margin:0; font-weight:700; letter-spacing:.2px; }
  h1 .sub { color:var(--dim); font-weight:400; font-size:13px; margin-left:8px; }
  .controls { display:flex; gap:14px; align-items:center; flex-wrap:wrap; margin-left:auto; }
  label.opt { color:var(--dim); display:flex; gap:6px; align-items:center; cursor:pointer; user-select:none; }
  input[type=text] { background:var(--panel2); border:1px solid var(--line); color:var(--txt);
    padding:7px 10px; border-radius:8px; width:150px; }
  button { background:var(--accent); color:#04121f; border:0; padding:9px 16px; border-radius:8px;
    font-weight:700; cursor:pointer; }
  button.secondary { background:var(--chip); color:var(--txt); border:1px solid var(--line); }
  button:disabled { opacity:.5; cursor:default; }
  main { padding:20px 24px; max-width:1400px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; margin-bottom:18px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
  .card h3 { margin:0 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:var(--dim); }
  .card .big { font-size:20px; font-weight:700; }
  .kv { display:flex; justify-content:space-between; gap:10px; padding:2px 0; }
  .kv .k { color:var(--dim); } .kv .v { text-align:right; word-break:break-word; }
  .tabs { display:flex; gap:8px; margin:6px 0 16px; flex-wrap:wrap; }
  .tab { padding:8px 14px; border-radius:9px; background:var(--panel2); border:1px solid var(--line);
    color:var(--dim); cursor:pointer; }
  .tab.active { background:var(--accent); color:#04121f; border-color:var(--accent); font-weight:700; }
  .panel { display:none; } .panel.active { display:block; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line);
    border-radius:12px; overflow:hidden; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.5px; cursor:pointer; position:sticky; top:69px; background:var(--panel2); }
  tr:last-child td { border-bottom:0; }
  tr.host { cursor:pointer; }
  tr.host:hover { background:#182234; }
  tr.detail td { background:var(--panel2); color:var(--dim); font-size:13px; }
  .chip { display:inline-block; padding:1px 8px; border-radius:999px; background:var(--chip);
    color:var(--txt); font-size:12px; margin:1px 3px 1px 0; }
  .badge-you { background:#123; color:var(--accent); border:1px solid var(--accent); }
  .badge-gw { background:#241f10; color:var(--yellow); border:1px solid var(--yellow); }
  .risk { color:var(--yellow); }
  .risk-dot { color:var(--red); font-weight:700; }
  .muted { color:var(--dim); }
  .toolbar { display:flex; gap:12px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
  .status { color:var(--dim); font-size:13px; min-height:18px; }
  .log { background:#05080d; border:1px solid var(--line); border-radius:10px; padding:10px 12px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--dim);
    max-height:180px; overflow:auto; white-space:pre-wrap; }
  a { color:var(--accent); }
  .spinner { width:16px; height:16px; border:2px solid var(--line); border-top-color:var(--accent);
    border-radius:50%; display:inline-block; animation:spin .8s linear infinite; vertical-align:-3px; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .empty { color:var(--dim); padding:20px; text-align:center; }
</style>
</head>
<body>
<header>
  <h1>Network Inventory <span class="sub" id="subtitle">local dashboard</span></h1>
  <div class="controls">
    <label class="opt"><input type="checkbox" id="opt_fast"> Fast</label>
    <label class="opt"><input type="checkbox" id="opt_offline"> Offline</label>
    <label class="opt"><input type="checkbox" id="opt_no_probe"> No port probe</label>
    <label class="opt"><input type="checkbox" id="opt_bt" checked> Bluetooth</label>
    <input type="text" id="opt_subnet" placeholder="subnet (auto)">
    <button id="run">Run scan</button>
    <button id="save" class="secondary" disabled>Save JSON</button>
  </div>
</header>
<main>
  <div class="toolbar">
    <div class="status" id="status">Ready. Click “Run scan”.</div>
  </div>
  <div class="log" id="log" style="display:none"></div>

  <div id="results" style="display:none">
    <div class="cards" id="cards"></div>
    <div class="tabs">
      <div class="tab active" data-tab="hosts">Hosts</div>
      <div class="tab" data-tab="exposure">Exposure</div>
      <div class="tab" data-tab="bluetooth">Bluetooth</div>
      <div class="tab" data-tab="device">This device</div>
      <div class="tab" data-tab="raw">Raw JSON</div>
    </div>

    <div class="panel active" id="panel-hosts">
      <div class="toolbar">
        <input type="text" id="filter" placeholder="Filter hosts (IP, name, vendor, type)…" style="width:320px">
        <label class="opt"><input type="checkbox" id="only_risk"> Only with exposure</label>
        <span class="muted" id="hostcount"></span>
      </div>
      <table id="hosts">
        <thead><tr>
          <th data-sort="ip">IP</th><th data-sort="guessed_type">Type</th>
          <th data-sort="vendor">Vendor / model</th><th data-sort="mac">MAC</th>
          <th data-sort="name">Name(s)</th><th data-sort="os_guess">OS</th>
          <th>Ports</th><th>Risk</th>
        </tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="panel" id="panel-exposure"></div>
    <div class="panel" id="panel-bluetooth"></div>
    <div class="panel" id="panel-device"></div>
    <div class="panel" id="panel-raw"><div class="log" style="max-height:600px" id="rawjson"></div></div>
  </div>
</main>

<script>
const TOKEN = "__TOKEN__";
let REPORT = null;
let sortKey = "ip", sortDir = 1;

const $ = s => document.querySelector(s);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ipNum = ip => (ip||"").split(".").reduce((a,o)=>a*256+(+o||0),0);

function tabTo(name){
  document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t.dataset.tab===name));
  document.querySelectorAll(".panel").forEach(p=>p.classList.toggle("active",p.id==="panel-"+name));
}
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>tabTo(t.dataset.tab));

let progressTimer = null;
async function pollProgress(){
  try{
    const r = await fetch(`/api/progress?token=${TOKEN}`);
    const d = await r.json();
    const log = $("#log");
    log.textContent = (d.lines||[]).join("\n");
    log.scrollTop = log.scrollHeight;
  }catch(e){}
}

async function runScan(){
  const btn = $("#run"); btn.disabled = true; $("#save").disabled = true;
  $("#log").style.display = "block";
  const started = Date.now();
  $("#status").innerHTML = `<span class="spinner"></span> Scanning… (this can take 15–60s)`;
  progressTimer = setInterval(pollProgress, 700); pollProgress();
  const p = new URLSearchParams({
    token: TOKEN,
    fast: $("#opt_fast").checked?1:0,
    offline: $("#opt_offline").checked?1:0,
    no_probe: $("#opt_no_probe").checked?1:0,
    no_bluetooth: $("#opt_bt").checked?0:1,
    subnet: $("#opt_subnet").value.trim(),
  });
  try{
    const r = await fetch(`/api/scan?${p.toString()}`);
    const d = await r.json();
    if(d.error) throw new Error(d.error);
    REPORT = d;
    render();
    const secs = ((Date.now()-started)/1000).toFixed(1);
    $("#status").textContent = `Done in ${secs}s — ${d.host_count} hosts, ${(d.bluetooth&&d.bluetooth.devices||[]).length} Bluetooth.`;
    $("#save").disabled = false;
    $("#results").style.display = "block";
  }catch(e){
    $("#status").innerHTML = `<span class="risk-dot">Error:</span> ${esc(e.message)}`;
  }finally{
    clearInterval(progressTimer); pollProgress();
    btn.disabled = false;
  }
}

function card(title, rows, big){
  let h = `<div class="card"><h3>${esc(title)}</h3>`;
  if(big) h += `<div class="big">${esc(big)}</div>`;
  for(const [k,v] of rows){ if(v) h += `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`; }
  return h + `</div>`;
}

function render(){
  const w = REPORT.wifi_summary||{}, pub = REPORT.public_ip||{}, dev = REPORT.device||{};
  $("#subtitle").textContent = (w.ssid?("· "+w.ssid):"") + (dev.macos_names&&dev.macos_names.ComputerName?(" · "+dev.macos_names.ComputerName):"");
  let cards = "";
  cards += card("Wi-Fi / LAN", [
    ["SSID", w.ssid],["Interface", w.interface],["This IP", (w.ipv4||[]).join(", ")],
    ["Gateway", w.gateway],["Channel", w.channel],["Security", w.security],["Signal", w.signal_noise],
  ]);
  cards += card("Public IP (WAN)", [
    ["ISP / org", pub.org],["Geo", [pub.city,pub.region,pub.country].filter(Boolean).join(", ")],
  ], pub.ip||pub.error||"—");
  cards += card("Counts", [
    ["Hosts", REPORT.host_count],["Others", REPORT.other_host_count],
    ["Exposure notes", (REPORT.hosts||[]).filter(h=>(h.risks||[]).length).length],
    ["Bluetooth", (REPORT.bluetooth&&REPORT.bluetooth.devices||[]).length],
  ], (REPORT.host_count||0)+" devices");
  cards += card("This device", [
    ["Model", dev.sysctl&&dev.sysctl["hw.model"]],["macOS", dev.sw_vers&&dev.sw_vers.ProductVersion],
    ["CPU", dev.sysctl&&dev.sysctl["machdep.cpu.brand_string"]],["Serial", dev.ioreg&&dev.ioreg.serial],
  ]);
  $("#cards").innerHTML = cards;

  renderHosts();
  renderExposure();
  renderBluetooth();
  renderDevice();
  $("#rawjson").textContent = JSON.stringify(REPORT, null, 2);
}

function hostMatches(h, q){
  if(!q) return true;
  const blob = [h.ip,h.guessed_type,h.vendor,h.model,h.mac,h.os_guess,(h.names||[]).join(" "),(h.open_ports||[]).join(" ")].join(" ").toLowerCase();
  return blob.includes(q.toLowerCase());
}

function renderHosts(){
  const q = $("#filter").value.trim();
  const onlyRisk = $("#only_risk").checked;
  let hosts = (REPORT.hosts||[]).filter(h=>hostMatches(h,q) && (!onlyRisk || (h.risks||[]).length));
  hosts.sort((a,b)=>{
    let av,bv;
    if(sortKey==="ip"){ av=ipNum(a.ip); bv=ipNum(b.ip); }
    else if(sortKey==="name"){ av=(a.names||[])[0]||""; bv=(b.names||[])[0]||""; }
    else { av=(a[sortKey]||"").toString().toLowerCase(); bv=(b[sortKey]||"").toString().toLowerCase(); }
    return (av>bv?1:av<bv?-1:0)*sortDir;
  });
  const tb = $("#hosts tbody"); tb.innerHTML = "";
  for(const h of hosts){
    const tr = document.createElement("tr"); tr.className="host";
    const tags = (h.is_self?'<span class="chip badge-you">YOU</span>':'') + (h.is_gateway?'<span class="chip badge-gw">GATEWAY</span>':'');
    const vendorModel = [h.model, (h.vendor&&!/randomized|administered/.test(h.vendor)?h.vendor:"")].filter(Boolean).join(" · ") || (h.vendor||"");
    const ports = (h.open_ports||[]).map(p=>`<span class="chip">${esc(p)}</span>`).join("");
    const risk = (h.risks||[]).length ? `<span class="risk-dot">●</span> ${(h.risks||[]).length}` : "";
    tr.innerHTML = `<td>${esc(h.ip)} ${tags}</td><td>${esc(h.guessed_type)}</td>
      <td>${esc(vendorModel)}</td><td class="muted">${esc(h.mac||"")}</td>
      <td>${esc((h.names||[]).slice(0,2).join(", "))}</td>
      <td class="muted">${esc((h.os_guess||"").split(" (")[0])}</td>
      <td>${ports}</td><td class="risk">${risk}</td>`;
    const detail = document.createElement("tr"); detail.className="detail"; detail.style.display="none";
    detail.innerHTML = `<td colspan="8">${hostDetail(h)}</td>`;
    tr.onclick = ()=>{ detail.style.display = detail.style.display==="none"?"":"none"; };
    tb.appendChild(tr); tb.appendChild(detail);
  }
  $("#hostcount").textContent = `${hosts.length} shown`;
}

function hostDetail(h){
  let out = [];
  if((h.names||[]).length) out.push(`<b>Names:</b> ${esc(h.names.join(", "))}`);
  if(h.model) out.push(`<b>Model:</b> ${esc(h.model)}`);
  if(h.os_guess) out.push(`<b>OS guess:</b> ${esc(h.os_guess)}`);
  if((h.ipv6||[]).length) out.push(`<b>IPv6:</b> ${esc(h.ipv6.join(", "))}`);
  if((h.mdns_services||[]).length) out.push(`<b>Bonjour:</b> ${esc(h.mdns_services.join(", "))}`);
  if(h.ssdp && Object.keys(h.ssdp).length) out.push(`<b>UPnP/SSDP:</b> ${esc(Object.entries(h.ssdp).map(([k,v])=>k+"="+v).join("; "))}`);
  if(h.banners && Object.keys(h.banners).length) out.push(`<b>Banners:</b> ${esc(Object.entries(h.banners).map(([k,v])=>k+": "+v).join("; "))}`);
  if((h.risks||[]).length) out.push(`<b class="risk">Exposure:</b> ${esc(h.risks.join(" | "))}`);
  if((h.source||[]).length) out.push(`<span class="muted">Seen via: ${esc(h.source.join(", "))}</span>`);
  return out.join("<br>") || '<span class="muted">No further detail.</span>';
}

function renderExposure(){
  const flagged = (REPORT.hosts||[]).filter(h=>(h.risks||[]).length);
  const el = $("#panel-exposure");
  if(!flagged.length){ el.innerHTML = `<div class="empty">No plaintext/admin services found on scanned ports. 🎉</div>`; return; }
  let h = `<p class="muted">Informational only — services reachable on your LAN, not exploited.</p>`;
  for(const host of flagged){
    h += `<div class="card" style="margin-bottom:10px"><h3>${esc(host.ip)} — ${esc(host.guessed_type)} ${esc((host.names||[])[0]||"")}</h3>`;
    for(const r of host.risks) h += `<div class="risk">• ${esc(r)}</div>`;
    h += `</div>`;
  }
  h += `<p class="muted">Hardening: disable Telnet/plaintext admin, isolate IoT on a guest VLAN/SSID, patch firmware, use strong unique passwords.</p>`;
  el.innerHTML = h;
}

function renderBluetooth(){
  const bt = REPORT.bluetooth||{}; const el = $("#panel-bluetooth");
  if(!bt.available){ el.innerHTML = `<div class="empty">No Bluetooth data (off or unsupported).</div>`; return; }
  const c = bt.controller||{};
  let h = card("Controller", [["Chipset",c.chipset],["Firmware",c.firmware],["State",c.state],["Vendor",c.vendor],["Transport",c.transport]]);
  const devs = bt.devices||[];
  h += `<p class="muted">Silent: paired/known devices macOS already tracks. Nothing was transmitted.</p>`;
  if(!devs.length){ h += `<div class="empty">Bluetooth on, but no paired/known devices right now.</div>`; }
  else {
    h += `<table><thead><tr><th>Name</th><th>Address</th><th>Type</th><th>Vendor</th><th>RSSI</th><th>Battery</th><th>State</th></tr></thead><tbody>`;
    for(const d of devs){
      h += `<tr><td>${esc(d.name)}</td><td class="muted">${esc(d.address||"")}</td>
        <td>${esc(d.minor_type||d.major_type||d.type||"")}</td><td>${esc(d.vendor||"")}</td>
        <td>${esc(d.rssi||"")}</td><td>${esc(d.battery||"")}</td>
        <td>${d.connected?'<span class="chip badge-you">connected</span>':'<span class="muted">paired</span>'}</td></tr>`;
    }
    h += `</tbody></table>`;
  }
  el.innerHTML = `<div class="cards">${h.split("</div>")[0]}</div>` + h.substring(h.indexOf("</div>")+6);
}

function renderDevice(){
  const d = REPORT.device||{}; const s = d.sysctl||{}, sw = d.sw_vers||{}, io = d.ioreg||{}, names = d.macos_names||{};
  let cards = "";
  cards += card("Identity", [["Computer", names.ComputerName],["Hostname", names.LocalHostName],
    ["User", d.username],["macOS", [sw.ProductName,sw.ProductVersion,sw.BuildVersion].filter(Boolean).join(" ")]]);
  cards += card("Hardware", [["Model", s["hw.model"]],["CPU", s["machdep.cpu.brand_string"]],
    ["Memory", d.memory_gb?d.memory_gb+" GB":""],["Serial", io.serial],["UUID", io.hardware_uuid]]);
  const dns = d.dns||{};
  cards += card("Routing / DNS", [["Gateway", (d.default_route||{}).gateway],
    ["Interface", (d.default_route||{}).interface],["DNS", (dns.nameservers||[]).join(", ")]]);
  let ifs = `<table><thead><tr><th>Interface</th><th>Kind</th><th>MAC</th><th>IPv4</th><th>Status</th></tr></thead><tbody>`;
  for(const i of (d.interfaces||[])){
    if(!(i.ipv4||[]).length && !i.mac) continue;
    ifs += `<tr><td>${esc(i.name)}</td><td class="muted">${esc(i.kind||i.media||"")}</td>
      <td class="muted">${esc(i.mac||"")}</td><td>${esc((i.ipv4||[]).join(", "))}</td><td class="muted">${esc(i.status||"")}</td></tr>`;
  }
  ifs += `</tbody></table>`;
  $("#panel-device").innerHTML = `<div class="cards">${cards}</div>` + ifs;
}

$("#run").onclick = runScan;
$("#filter").oninput = renderHosts;
$("#only_risk").onchange = renderHosts;
document.querySelectorAll("#hosts th[data-sort]").forEach(th=>{
  th.onclick = ()=>{ const k=th.dataset.sort; if(sortKey===k) sortDir*=-1; else {sortKey=k; sortDir=1;} renderHosts(); };
});
$("#save").onclick = ()=>{
  const blob = new Blob([JSON.stringify(REPORT,null,2)], {type:"application/json"});
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
  a.download = "network_report.json"; a.click();
};
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Local web-dashboard GUI for network_inventory.")
    ap.add_argument("--port", type=int, default=8765, help="Port to bind on 127.0.0.1 (default 8765)")
    ap.add_argument("--no-open", action="store_true", help="Do not auto-open the browser")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Network Inventory dashboard: {url}")
    print("Bound to localhost only. Press Ctrl+C to stop.")
    if not args.no_open:
        threading.Thread(target=lambda: (time.sleep(0.6), webbrowser.open(url)), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
