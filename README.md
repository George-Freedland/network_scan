# network_inventory

A single-file, zero-dependency Python tool that tells you everything it can about:

- **this device** — hardware, macOS/kernel, serial, CPU/RAM, battery, every interface/IP/MAC, DNS, routes, listening ports, and current outbound connections;
- **the Wi-Fi / LAN session** — SSID, channel, PHY, security, signal, DHCP, gateway, and your public/WAN IP (with a VPN tunnel called out separately so it never gets scanned as the LAN);
- **every other host on your subnet** — IP, MAC, vendor, hostnames, Bonjour/mDNS services, **SSDP/UPnP model + manufacturer + serial**, a **TTL-based OS guess**, open identification ports with banners, a **best-effort device type**, and a **defensive exposure assessment**;
- **paired/known Bluetooth devices** — controller info plus each device's name, address, type, vendor, RSSI, and battery, read silently from the local system inventory (no radio inquiry, nothing transmitted, no device contacted);
- **nearby BLE advertisers** (optional, with `bleak`) — devices broadcasting around you (other phones, AirTags/Find My tags, AirPods, beacons, Govee/IoT sensors, TVs) with RSSI, manufacturer/company ID, and Apple continuity type — receive-only, so nothing is paired or contacted.

It runs on the Python 3.9+ standard library alone and needs **no root**. Optional packages (below) make it even better if installed. Two front-ends share the same engine: the standalone CLI (`network_inventory.py`) and a local web dashboard (`network_inventory_gui.py`).

> Use this only on networks you own or are explicitly authorized to inspect.

## Usage

Command line (the standalone script — unchanged):

```bash
python3 network_inventory.py                 # full human-readable report
python3 network_inventory.py --json -o report.json
python3 network_inventory.py --fast          # quicker: gateway-only ping sweep, shorter listens
python3 network_inventory.py --offline       # no public-IP / online MAC-vendor HTTP calls
python3 network_inventory.py --no-probe      # skip connecting to identification ports
python3 network_inventory.py --no-bluetooth  # skip the silent Bluetooth inventory
python3 network_inventory.py --ble-scan      # also scan nearby BLE advertisers (needs `bleak`)
python3 network_inventory.py --subnet 192.168.1.0/24
```

GUI (local web dashboard — opens in your browser, no dependencies):

```bash
python3 network_inventory_gui.py             # starts on http://127.0.0.1:8765 and opens it
python3 network_inventory_gui.py --port 9000 --no-open
```

The dashboard has options (Fast / Offline / No probe / Bluetooth / subnet), a live
progress log, a sortable + filterable host table with expandable details, and
separate Exposure, Bluetooth, This-device, and Raw-JSON views (with a "Save JSON"
button). The server binds to `127.0.0.1` only and gates its API with a per-session
token, and it does not send CORS headers — so other websites and other machines
cannot read your results.

Useful CLI flags: `--mdns-seconds N` (Bonjour/SSDP listen time), `--probe-timeout S` (per-port connect timeout), `--no-color`.

## How devices are identified

The script layers several passive/lightweight techniques and merges the results per host:

| Technique | What it yields |
|-----------|----------------|
| ARP / NDP tables + ping sweep | which IPs/MACs are actually present |
| MAC OUI lookup | hardware vendor (skipped for randomized/private MACs) |
| mDNS / Bonjour | hostnames, services, and Apple `device-info` model codes |
| **SSDP / UPnP** | friendlyName, manufacturer, **modelName**, serial (great for TVs, media boxes, routers, IoT) |
| Reverse DNS + NetBIOS | additional names |
| TTL from ping | coarse OS class (unix/apple vs Windows vs IoT vs network gear) |
| Connect-only port ID | SSH/HTTP/SMB/AirPlay/RTSP/etc. plus banners |

"Exposure findings" flags services reachable on your LAN that are worth reviewing (plaintext admin, Telnet, exposed databases, VNC/RDP, unauthenticated MQTT, router admin over plain HTTP, very old service banners). **These are identification-only observations — the script never sends an exploit or tries credentials.**

## Optional dependencies

Everything works without these; install any of them to improve results:

```bash
pip install -r requirements-optional.txt
```

- **mac-vendor-lookup** — full offline IEEE OUI database, so vendors resolve without any network call (`--offline` friendly). The script auto-detects and uses it if importable.
- **bleak** — enables nearby BLE advertiser discovery via `--ble-scan` (CLI) and the "Nearby BLE" toggle (GUI). Receive-only; no pairing or connecting.
- The report already reads a local `nmap`/Wireshark `manuf` file if one is present on disk.

For heavier analysis than this script targets, the ecosystem worth knowing:

- **scapy** — raw packet crafting for ARP/OS fingerprinting (needs root).
- **zeroconf** — robust, spec-complete mDNS/Bonjour browser.
- **async-upnp-client** / **ssdpy** — fuller UPnP/SSDP control and description parsing.
- Tools like **Wireshark**, **nmap**, and **Fing** go further (JA3/JA4 TLS fingerprints, p0f TCP signatures, full service/version detection) at the cost of setup, privileges, or being a GUI app.

## Notes & limitations

- Sleeping phones often don't answer ARP; rerun while they're awake.
- Modern phones randomize their Wi-Fi MAC, which intentionally hides the vendor.
- Some Wi-Fi fields (BSSID, RSSI) require Location permission or `sudo wdutil info` on recent macOS.
- Discovery is limited to your `/24` even if the interface reports a larger prefix.
- The Bluetooth list is **paired/known devices only**, read from the local system inventory — it is silent and contacts nothing.
- Nearby *unpaired* BLE discovery (`--ble-scan` / GUI "Nearby BLE") needs the optional `bleak` package. It is receive-only — it reads the advertisement packets devices already broadcast to everyone in range (name, RSSI, manufacturer/company ID, Apple continuity type such as AirTag/AirPods/Nearby, service UUIDs) and never pairs, connects, or writes, so no device is contacted and no person is notified. macOS will ask once for Bluetooth permission for your terminal.
