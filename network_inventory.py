#!/usr/bin/env python3
"""Local Wi-Fi / LAN inventory for a machine you own.

Collects:
  - this device (hardware, OS, interfaces, addresses, DNS, routes)
  - the active Wi-Fi / LAN session (SSID, PHY, DHCP, gateway, public IP)
  - other hosts on the local subnet (IP, MAC, vendor, names, Bonjour, SSDP/UPnP
    model, TTL/OS guess, light service ID, and a defensive exposure assessment)

Runs on the Python standard library alone (no root needed). Optional packages
improve results if present (see README): mac-vendor-lookup for full offline OUI.

Use only on networks you own or are authorized to inspect.
Tested on macOS; Linux fallbacks included.

  python3 network_inventory.py
  python3 network_inventory.py --json -o report.json
  python3 network_inventory.py --fast
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

IS_TTY = sys.stdout.isatty()


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"
    WHITE = "\033[97m"


def _c(code: str, text: str) -> str:
    if not IS_TTY:
        return text
    return f"{code}{text}{Style.RESET}"


def heading(title: str) -> None:
    bar = "─" * 72
    print()
    print(_c(Style.CYAN + Style.BOLD, bar))
    print(_c(Style.CYAN + Style.BOLD, f"  {title}"))
    print(_c(Style.CYAN + Style.BOLD, bar))


def kv(key: str, value: Any, indent: int = 0) -> None:
    if value is None or value == "" or value == [] or value == {}:
        return
    pad = " " * indent
    key_s = _c(Style.DIM, f"{key}:")
    if isinstance(value, (list, tuple)):
        print(f"{pad}{key_s} {', '.join(str(v) for v in value)}")
    else:
        print(f"{pad}{key_s} {value}")


def run(
    args: list[str],
    timeout: float = 8.0,
    input_text: str | None = None,
) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr and proc.returncode != 0 else "")


def run_ok(args: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 1, "", ""


def which(name: str) -> str | None:
    return shutil.which(name)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

COMMON_MDNS_SERVICES = [
    "_services._dns-sd._udp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_companion-link._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_mediaremotetv._tcp.local",
    "_appletv-v2._tcp.local",
    "_apple-mobdev2._tcp.local",
    "_rdlink._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_sleep-proxy._udp.local",
    "_airport._tcp.local",
    "_presence._tcp.local",
    "_home-sharing._tcp.local",
    "_daap._tcp.local",
    "_touch-able._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    "_uscan._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_adisk._tcp.local",
    "_nfs._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_googlecast._tcp.local",
    "_androidtvremote2._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_nvstream._tcp.local",
    "_plex._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_hue._tcp.local",
    "_elg._tcp.local",
    "_esphomelib._tcp.local",
]

# Identification-only ports. Connect (and, for a few, read a greeting) to tell
# what a device is. "risk" flags plaintext / commonly-exposed admin surfaces so
# the report can point them out — it never sends an exploit payload.
IDENT_PORTS = [
    (21, "ftp", "plaintext file transfer"),
    (22, "ssh", None),
    (23, "telnet", "plaintext remote login (insecure)"),
    (53, "dns", None),
    (80, "http", None),
    (111, "rpcbind", None),
    (135, "msrpc", "Windows RPC exposed"),
    (139, "netbios-ssn", "legacy SMB/NetBIOS"),
    (443, "https", None),
    (445, "smb", "file sharing exposed"),
    (515, "lpd", None),
    (548, "afp", None),
    (554, "rtsp", "camera / streaming"),
    (631, "ipp", None),
    (1883, "mqtt", "unauthenticated IoT bus if open"),
    (1900, "ssdp/upnp", None),
    (2323, "telnet-alt", "plaintext remote login (insecure)"),
    (3306, "mysql", "database exposed to LAN"),
    (3389, "rdp", "remote desktop exposed"),
    (5000, "upnp-airplay", None),
    (5001, "synology-https", None),
    (5060, "sip", None),
    (5357, "wsd", None),
    (5432, "postgres", "database exposed to LAN"),
    (5555, "adb", "Android debug bridge (if open, remote control)"),
    (5900, "vnc", "remote desktop exposed"),
    (6379, "redis", "unauthenticated cache if open"),
    (7000, "airplay", None),
    (8008, "chromecast", None),
    (8009, "chromecast-tls", None),
    (8080, "http-alt", None),
    (8443, "https-alt", None),
    (8883, "mqtt-tls", None),
    (9000, "http-admin", None),
    (9100, "jetdirect", "raw printing"),
    (32400, "plex", None),
    (49152, "upnp-http", None),
    (62078, "ios-lockdown", None),
]

# Apple model identifiers (from mDNS _device-info "model=" and UPnP) -> readable.
APPLE_MODELS: dict[str, str] = {
    "MacBookAir10,1": "MacBook Air (M1, 2020)",
    "MacBookAir": "MacBook Air",
    "MacBookPro": "MacBook Pro",
    "MacBook": "MacBook",
    "Macmini": "Mac mini",
    "iMac": "iMac",
    "MacStudio": "Mac Studio",
    "MacPro": "Mac Pro",
    "iPhone": "iPhone",
    "iPad": "iPad",
    "iPod": "iPod touch",
    "Watch": "Apple Watch",
    "AudioAccessory": "HomePod",
    "AppleTV": "Apple TV",
    "J413AP": "MacBook Air (M2)",
    "RP": "AirPort / Time Capsule",
}

# UPnP / SSDP server & model substrings -> friendly device class.
SSDP_HINTS = [
    ("samsung", "Samsung TV"),
    ("lg electronics", "LG TV"),
    ("webos", "LG TV"),
    ("roku", "Roku"),
    ("sonos", "Sonos speaker"),
    ("chromecast", "Chromecast"),
    ("bravia", "Sony Bravia TV"),
    ("vizio", "Vizio TV"),
    ("hisense", "Hisense TV"),
    ("tcl", "TCL TV"),
    ("xbox", "Xbox"),
    ("playstation", "PlayStation"),
    ("directv", "DirecTV receiver"),
    ("denon", "Denon receiver"),
    ("yamaha", "Yamaha receiver"),
    ("bose", "Bose speaker"),
    ("printer", "Printer"),
    ("synology", "Synology NAS"),
    ("qnap", "QNAP NAS"),
    ("plex", "Plex server"),
    ("router", "Router / gateway"),
    ("gateway", "Router / gateway"),
    ("wemo", "Belkin Wemo"),
    ("hue", "Philips Hue bridge"),
    ("ring", "Ring device"),
    ("nest", "Google Nest"),
    ("shield", "NVIDIA Shield"),
    ("fire tv", "Amazon Fire TV"),
    ("echo", "Amazon Echo"),
    ("kodi", "Kodi / media center"),
]

# Chip/module maker in the OUI -> a reasonable device-class guess when nothing
# else identifies the host. These vendors ship inside many consumer gadgets.
VENDOR_HINTS = [
    ("espressif", "ESP32/ESP8266 smart-home device"),
    ("raspberry", "Raspberry Pi"),
    ("amazon", "Amazon device (Echo / Fire / Kindle)"),
    ("google", "Google / Nest device"),
    ("nest", "Google Nest device"),
    ("roku", "Roku"),
    ("sonos", "Sonos speaker"),
    ("tuya", "Tuya smart-home device"),
    ("ring", "Ring device"),
    ("wyze", "Wyze camera / sensor"),
    ("ecobee", "ecobee thermostat"),
    ("harman", "Harman/JBL speaker"),
    ("azurewave", "Wi-Fi module (TV / console / IoT)"),
    ("ampak", "Wi-Fi module (TV / IoT device)"),
    ("gaoshengda", "Amazon/IoT device (Wi-Fi module)"),
    ("cloud network technology", "Wi-Fi module (Foxconn — phone / IoT)"),
    ("murata", "Wi-Fi module (IoT / appliance)"),
    ("texas instruments", "IoT / embedded device (TI chip)"),
    ("realtek", "IoT / embedded device (Realtek chip)"),
    ("shenzhen", "IoT device (Shenzhen OEM)"),
]

OUI_FALLBACK: dict[str, str] = {
    "000C29": "VMware",
    "00155D": "Microsoft Hyper-V",
    "001A11": "Google",
    "001B63": "Apple",
    "001C42": "Parallels",
    "001D0F": "TP-Link",
    "002272": "American Micro-Fuel",
    "00259D": "Amazon",
    "0050F2": "Microsoft",
    "08EA44": "Extreme Networks",
    "0C47A9": "Intel",
    "107B44": "ASUSTek",
    "18B430": "Nest / Google",
    "1C69A5": "BlackBerry",
    "247189": "Texas Instruments",
    "28C2DD": "AzureWave",
    "2C54CF": "LG Electronics",
    "30AEA4": "Espressif",
    "3C5A37": "Samsung",
    "3C6A7D": "Niigata Power",
    "44D9E7": "Ubiquiti",
    "485D36": "Verizon",
    "4C50DD": "Hangzhou Xiongmai",
    "50C7BF": "TP-Link",
    "525400": "QEMU/KVM",
    "58EF68": "Belkin",
    "5CF370": "CC&C / Realtek",
    "606405": "Texas Instruments",
    "626470": "Espressif (locally administered)",
    "68FF7B": "TP-Link",
    "70B3D5": "IEEE registered block",
    "74DA88": "TP-Link",
    "78A5DD": "Google Nest",
    "7C49EB": "XIAOMI",
    "804E70": "Samsung",
    "84C78F": "STMicroelectronics",
    "8CAACE": "Xiaomi",
    "90CAFA": "Google",
    "94B97E": "Espressif",
    "98DAA7": "Amazon Echo",
    "A0CEC8": "CE LINK",
    "A4C138": "Telink Semiconductor",
    "ACBC32": "Apple",
    "B0A737": "Espressif",
    "B4E62D": "Espressif",
    "B827EB": "Raspberry Pi",
    "BCFF4D": "Espressif",
    "C46E7B": "SHENZHEN MERCURY",
    "CC50E3": "Espressif",
    "D8A01D": "Espressif",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "E8DB84": "Espressif",
    "F0B429": "Xiaomi",
    "F0D1A9": "Apple",
    "F4F5D8": "Google",
    "F8F1B6": "Motorola",
    "FC017C": "Hon Hai / Foxconn",
}

APPLE_OUI_HINTS = (
    "00:03:93",
    "00:0A:27",
    "00:0A:95",
    "00:1B:63",
    "00:1E:52",
    "00:1F:F3",
    "00:23:12",
    "00:23:32",
    "00:23:6C",
    "00:25:00",
    "00:26:4A",
    "00:26:B0",
    "00:26:BB",
    "00:88:65",
    "04:0C:CE",
    "04:15:52",
    "08:00:07",
    "08:66:98",
    "08:74:02",
    "0C:74:C2",
    "10:40:F3",
    "10:93:E9",
    "14:10:9F",
    "18:65:90",
    "18:AF:61",
    "1C:1A:C0",
    "20:78:F0",
    "24:A0:74",
    "28:6A:BA",
    "28:CF:E9",
    "2C:1F:23",
    "34:15:9E",
    "38:C9:86",
    "3C:07:54",
    "40:33:1A",
    "40:A6:D9",
    "44:2A:60",
    "48:43:7C",
    "4C:32:75",
    "50:EA:D6",
    "54:26:96",
    "58:55:CA",
    "5C:95:AE",
    "60:33:4B",
    "60:C5:47",
    "64:70:33",
    "68:96:7B",
    "6C:4D:73",
    "70:56:81",
    "78:4F:43",
    "7C:04:D0",
    "7C:6D:62",
    "80:BE:05",
    "80:E6:50",
    "84:38:35",
    "88:66:5A",
    "8C:29:37",
    "90:27:E4",
    "90:B0:ED",
    "98:01:A7",
    "9C:20:7B",
    "9C:F3:87",
    "A4:83:E7",
    "A8:60:B6",
    "AC:87:A3",
    "B0:65:BD",
    "B8:09:8A",
    "BC:52:B7",
    "C0:A5:DD",
    "C8:69:CD",
    "CC:20:E8",
    "D0:23:DB",
    "D8:30:62",
    "DC:2B:2A",
    "E0:AC:CB",
    "E4:CE:8F",
    "F0:18:98",
    "F0:DB:F8",
    "F4:0F:24",
    "F8:27:93",
    "FC:25:3F",
)


@dataclass
class Interface:
    name: str
    mac: str | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    netmasks: list[str] = field(default_factory=list)
    status: str | None = None
    mtu: int | None = None
    media: str | None = None
    kind: str | None = None


@dataclass
class Host:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    names: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    mdns_services: list[str] = field(default_factory=list)
    txt: dict[str, str] = field(default_factory=dict)
    open_ports: list[str] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    ssdp: dict[str, str] = field(default_factory=dict)
    model: str | None = None
    os_guess: str | None = None
    ttl: int | None = None
    risks: list[str] = field(default_factory=list)
    guessed_type: str | None = None
    is_self: bool = False
    is_gateway: bool = False


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------

def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().lower().replace("-", ":")
    if mac in {"(incomplete)", "ff:ff:ff:ff:ff:ff"}:
        return None
    parts = mac.split(":")
    if len(parts) != 6:
        return None
    try:
        parts = [f"{int(p, 16):02x}" for p in parts]
    except ValueError:
        return None
    return ":".join(parts)


def mac_prefix24(mac: str) -> str:
    return mac.replace(":", "")[:6].upper()


def looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def first_nonempty(*vals: Any) -> Any:
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None


def is_tunnel_name(name: str) -> bool:
    n = name.lower()
    return n.startswith(("utun", "ipsec", "ppp", "tun", "tap", "wg", "gif", "stf"))


def is_unicast_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return not (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
    )


def is_unicast_mac(mac: str | None) -> bool:
    n = norm_mac(mac)
    if not n:
        return False
    try:
        return (int(n.split(":")[0], 16) & 0x01) == 0
    except ValueError:
        return False


def pretty_apple(val: str | None) -> str | None:
    if not val:
        return val
    val = re.sub(r"^.*security_mode_", "", val)
    val = re.sub(r"^.*network_type_", "", val)
    val = re.sub(r"^spairport_", "", val)
    return val.replace("_", " ").strip()


def pick_lan_interface(ifaces: list[Interface]) -> Interface | None:
    """Prefer Wi-Fi / Ethernet LAN, never a VPN tunnel."""
    scored: list[tuple[int, Interface]] = []
    for iface in ifaces:
        if not iface.ipv4 or iface.name.startswith("lo"):
            continue
        kind = (iface.kind or "").lower()
        name = iface.name.lower()
        score = 0
        if kind in {"wi-fi", "wifi"}:
            score += 100
        elif "thunderbolt bridge" in kind:
            score -= 20
        elif "ethernet" in kind:
            score += 80
        elif name.startswith("en"):
            score += 50
        if is_tunnel_name(name) or "vpn" in kind:
            score -= 200
        if iface.status in {"active", "up"}:
            score += 10
        try:
            if ipaddress.IPv4Address(iface.ipv4[0]).is_private:
                score += 20
        except ipaddress.AddressValueError:
            continue
        scored.append((score, iface))
    scored.sort(key=lambda x: -x[0])
    if scored and scored[0][0] > 0:
        return scored[0][1]
    return None


# ---------------------------------------------------------------------------
# Local device
# ---------------------------------------------------------------------------

def macos_hardware_port_map() -> dict[str, str]:
    """device (en0) -> 'Wi-Fi' / 'Ethernet' / ..."""
    out = run(["networksetup", "-listallhardwareports"], timeout=5)
    mapping: dict[str, str] = {}
    port = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            mapping[line.split(":", 1)[1].strip()] = port
            port = None
    return mapping


def parse_ifconfig() -> list[Interface]:
    out = run(["ifconfig"], timeout=5)
    if not out:
        out = run(["ip", "-o", "addr"], timeout=5)
        return _parse_ip_addr(out) if out else []

    ifaces: list[Interface] = []
    current: Interface | None = None
    for line in out.splitlines():
        if line and not line.startswith("\t") and not line.startswith(" "):
            name = line.split(":", 1)[0].split()[0]
            current = Interface(name=name)
            ifaces.append(current)
            flags = re.search(r"flags=\S+\s*<([^>]+)>", line)
            if flags:
                current.status = "up" if "UP" in flags.group(1).split(",") else "down"
            mtu = re.search(r"mtu (\d+)", line)
            if mtu:
                current.mtu = int(mtu.group(1))
            continue
        if current is None:
            continue
        s = line.strip()
        if s.startswith("ether ") or s.startswith("lladdr "):
            current.mac = norm_mac(s.split()[1])
        elif s.startswith("inet "):
            parts = s.split()
            current.ipv4.append(parts[1].split("/")[0])
            if "netmask" in parts:
                idx = parts.index("netmask")
                mask = parts[idx + 1]
                if mask.startswith("0x"):
                    current.netmasks.append(_hex_netmask(mask))
                else:
                    current.netmasks.append(mask)
        elif s.startswith("inet6 "):
            addr = s.split()[1].split("%")[0]
            current.ipv6.append(addr)
        elif s.startswith("status:"):
            current.status = s.split(":", 1)[1].strip()
        elif s.startswith("media:"):
            current.media = s.split(":", 1)[1].strip()
    return ifaces


def _parse_ip_addr(out: str) -> list[Interface]:
    by_name: dict[str, Interface] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1].rstrip(":")
        iface = by_name.setdefault(name, Interface(name=name))
        fam = parts[2]
        addr = parts[3]
        if fam == "inet":
            ip, _, pfx = addr.partition("/")
            iface.ipv4.append(ip)
            if pfx:
                try:
                    net = ipaddress.IPv4Network(f"0.0.0.0/{pfx}", strict=False)
                    iface.netmasks.append(str(net.netmask))
                except ValueError:
                    pass
        elif fam == "inet6":
            iface.ipv6.append(addr.split("/")[0].split("%")[0])
    return list(by_name.values())


def _hex_netmask(mask: str) -> str:
    try:
        value = int(mask, 16)
        return socket.inet_ntoa(struct.pack(">I", value))
    except (ValueError, OSError):
        return mask


def default_route() -> dict[str, str]:
    info: dict[str, str] = {}
    out = run(["route", "-n", "get", "default"], timeout=4)
    if out:
        for line in out.splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if k in {"gateway", "interface", "mac"}:
                    info[k] = v
        return info
    out = run(["ip", "route", "show", "default"], timeout=4)
    m = re.search(r"default via (\S+) dev (\S+)", out)
    if m:
        info["gateway"] = m.group(1)
        info["interface"] = m.group(2)
    return info


def routing_table() -> str:
    out = run(["netstat", "-rn", "-f", "inet"], timeout=4)
    if out:
        return out.strip()
    return run(["ip", "route"], timeout=4).strip()


def dns_config() -> dict[str, Any]:
    cfg: dict[str, Any] = {"nameservers": [], "search": [], "scoped": []}
    out = run(["scutil", "--dns"], timeout=5)
    if out:
        current: dict[str, Any] = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("resolver #"):
                if current:
                    cfg["scoped"].append(current)
                current = {"id": line}
            elif line.startswith("nameserver["):
                ip = line.split(":", 1)[1].strip()
                current.setdefault("nameservers", []).append(ip)
                if ip not in cfg["nameservers"]:
                    cfg["nameservers"].append(ip)
            elif line.startswith("search domain["):
                dom = line.split(":", 1)[1].strip()
                current.setdefault("search", []).append(dom)
                if dom not in cfg["search"]:
                    cfg["search"].append(dom)
            elif line.startswith("domain"):
                current["domain"] = line.split(":", 1)[1].strip()
            elif line.startswith("if_index"):
                current["interface"] = line.split(":", 1)[1].strip()
        if current:
            cfg["scoped"].append(current)
        return cfg
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    cfg["nameservers"].append(line.split()[1])
                elif line.startswith("search"):
                    cfg["search"].extend(line.split()[1:])
    except OSError:
        pass
    return cfg


def proxy_config() -> dict[str, str]:
    out = run(["scutil", "--proxy"], timeout=4)
    interesting = {}
    for line in out.splitlines():
        line = line.strip()
        if any(k in line for k in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "HTTPProxy", "HTTPPort", "HTTPSProxy", "ExceptionsList", "ProxyAutoConfigURLString")):
            if ":" in line:
                k, v = line.split(":", 1)
                interesting[k.strip().strip("'")] = v.strip()
    return interesting


def macos_names() -> dict[str, str]:
    names = {}
    for key in ("ComputerName", "LocalHostName", "HostName"):
        val = run(["scutil", "--get", key], timeout=3).strip()
        if val and "not set" not in val.lower():
            names[key] = val
    return names


def sysctl_n(*keys: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in keys:
        val = run(["sysctl", "-n", key], timeout=3).strip()
        if val:
            out[key] = val
    return out


def ioreg_serial() -> dict[str, str]:
    out = run(["ioreg", "-d2", "-c", "IOPlatformExpertDevice"], timeout=5)
    found: dict[str, str] = {}
    for key, label in (
        ("IOPlatformSerialNumber", "serial"),
        ("IOPlatformUUID", "hardware_uuid"),
        ("model", "model_id"),
        ("board-id", "board_id"),
    ):
        m = re.search(rf'"{key}"\s*=\s*(?:<"([^"]+)">|"([^"]+)")', out)
        if m:
            found[label] = m.group(1) or m.group(2)
    return found


def sw_vers() -> dict[str, str]:
    out = run(["sw_vers"], timeout=4)
    data = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def battery() -> str | None:
    out = run(["pmset", "-g", "batt"], timeout=4).strip()
    return out or None


def uptime_boot() -> dict[str, str]:
    info = {}
    out = run(["uptime"], timeout=3).strip()
    if out:
        info["uptime"] = out
    out = run(["sysctl", "-n", "kern.boottime"], timeout=3).strip()
    if out:
        info["boottime_raw"] = out
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            ts = datetime.fromtimestamp(int(m.group(1)))
            info["booted_at"] = ts.isoformat(sep=" ", timespec="seconds")
    return info


def listening_and_connections() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"listening": [], "established_remotes": []}
    out = run(["lsof", "+c", "32", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=6)
    seen: set[str] = set()
    listening: list[str] = []
    if out:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            cmd, pid = parts[0], parts[1]
            name = parts[-2] if parts[-1].startswith("(") else parts[-1]
            key = f"{cmd}|{name}"
            if key in seen:
                continue
            seen.add(key)
            listening.append(f"{name:<22} {cmd}  pid={pid}")
    if not listening:
        out = run(["netstat", "-an", "-p", "tcp"], timeout=6)
        for line in out.splitlines():
            if "LISTEN" in line:
                listening.append(" ".join(line.split()[:6]))
    result["listening"] = listening[:60]

    remotes: dict[str, int] = defaultdict(int)
    out = run(["lsof", "+c", "32", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=6)
    if out:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            name = parts[-2] if "->" in parts[-2] else (parts[-1] if "->" in parts[-1] else "")
            if "->" not in name:
                continue
            _local, remote = name.split("->", 1)
            remotes[remote] += 1
    else:
        out = run(["netstat", "-an", "-p", "tcp"], timeout=6)
        for line in out.splitlines():
            if "ESTABLISHED" in line:
                parts = line.split()
                if len(parts) >= 5:
                    remotes[parts[4]] += 1
    top = sorted(remotes.items(), key=lambda x: -x[1])[:40]
    result["established_remotes"] = [f"{addr}  ({n} conn)" if n > 1 else addr for addr, n in top]
    return result


def local_users() -> list[str]:
    out = run(["who"], timeout=3)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines


def collect_device() -> dict[str, Any]:
    uname = platform.uname()
    ifaces = parse_ifconfig()
    port_map = macos_hardware_port_map() if sys.platform == "darwin" else {}
    for iface in ifaces:
        iface.kind = port_map.get(iface.name)
    ctl = sysctl_n(
        "hw.model",
        "machdep.cpu.brand_string",
        "hw.ncpu",
        "hw.physicalcpu",
        "hw.logicalcpu",
        "hw.memsize",
        "kern.ostype",
        "kern.osrelease",
        "kern.version",
        "kern.hostname",
    )
    mem = ctl.get("hw.memsize")
    mem_gb = None
    if mem and mem.isdigit():
        mem_gb = round(int(mem) / (1024**3), 2)

    device = {
        "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "username": os.environ.get("USER") or os.environ.get("LOGNAME"),
        "home": os.path.expanduser("~"),
        "hostname_platform": socket.gethostname(),
        "fqdn": (lambda n: None if n.endswith(".arpa") else n)(socket.getfqdn()),
        "uname": {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
        },
        "python": sys.version.split()[0],
        "timezone": time.tzname,
        "locale": os.environ.get("LANG"),
        "shell": os.environ.get("SHELL"),
        "terminal": os.environ.get("TERM_PROGRAM") or os.environ.get("TERM"),
        "macos_names": macos_names(),
        "sw_vers": sw_vers(),
        "sysctl": ctl,
        "memory_gb": mem_gb,
        "ioreg": ioreg_serial(),
        "battery": battery(),
        "uptime": uptime_boot(),
        "logged_in": local_users(),
        "interfaces": [asdict(i) for i in ifaces],
        "default_route": default_route(),
        "dns": dns_config(),
        "proxy": proxy_config(),
        "routing_table": routing_table(),
        "sockets": listening_and_connections(),
    }
    return device, ifaces


# ---------------------------------------------------------------------------
# Bluetooth (silent — reads local system inventory, transmits nothing)
# ---------------------------------------------------------------------------

def collect_bluetooth() -> dict[str, Any]:
    """Paired/connected Bluetooth devices + controller, from system_profiler.

    This only reads what macOS already knows locally. It does not power on the
    radio, page, inquire, or advertise, so no nearby device is contacted or
    notified. Nearby *unpaired* discovery would need an active scan and the
    optional `bleak` package; it is intentionally not done here.
    """
    result: dict[str, Any] = {"controller": {}, "devices": [], "available": False}
    if sys.platform != "darwin":
        return result
    out = run(["system_profiler", "SPBluetoothDataType", "-json"], timeout=20)
    if not out.strip():
        return result
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return result
    blocks = data.get("SPBluetoothDataType") or []
    if not blocks:
        return result
    result["available"] = True
    block = blocks[0]

    ctrl = block.get("controller_properties") or {}
    result["controller"] = {
        "chipset": ctrl.get("controller_chipset"),
        "firmware": ctrl.get("controller_firmwareVersion"),
        "address": ctrl.get("controller_address"),
        "state": ctrl.get("controller_state"),
        "discoverable": ctrl.get("controller_discoverable"),
        "vendor": ctrl.get("controller_vendorID"),
        "transport": ctrl.get("controller_transport"),
        "services": ctrl.get("controller_supportedServices"),
    }

    def parse_devices(entries: list[Any], connected: bool) -> None:
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            for name, props in entry.items():
                if not isinstance(props, dict):
                    continue
                addr = props.get("device_address") or props.get("device_addr")
                dev = {
                    "name": name,
                    "address": addr,
                    "connected": connected,
                    "minor_type": props.get("device_minorType") or props.get("device_minorClassOfDevice_string"),
                    "major_type": props.get("device_majorType") or props.get("device_majorClassOfDevice_string"),
                    "type": props.get("device_type"),
                    "vendor_id": props.get("device_vendorID"),
                    "product_id": props.get("device_productID"),
                    "firmware": props.get("device_firmwareVersion"),
                    "rssi": props.get("device_rssi") or props.get("device_RSSI"),
                    "battery": props.get("device_batteryLevelMain") or props.get("device_batteryLevel"),
                    "services": props.get("device_services"),
                    "vendor": vendor_offline(addr) if addr else None,
                }
                result["devices"].append({k: v for k, v in dev.items() if v not in (None, "")})

    for key in ("device_connected", "devices_list"):
        parse_devices(block.get(key) or [], connected=(key == "device_connected"))
    parse_devices(block.get("device_not_connected") or [], connected=False)

    # De-dupe by address, prefer the connected record.
    by_addr: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for dev in result["devices"]:
        key = dev.get("address") or dev.get("name")
        if key not in by_addr:
            by_addr[key] = dev
            order.append(key)
        elif dev.get("connected") and not by_addr[key].get("connected"):
            by_addr[key] = dev
    result["devices"] = [by_addr[k] for k in order]
    return result


# ---------------------------------------------------------------------------
# Nearby BLE scan (optional, needs `bleak`) — receive-oriented, notifies no one
# ---------------------------------------------------------------------------

# Registered Bluetooth SIG company identifiers (small common subset). Unknown
# IDs are shown as hex. See the SIG assigned-numbers list for the full set.
BLE_COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0171: "Amazon",
    0x0087: "Garmin",
    0x00D2: "Bose",
    0x05A7: "Sonos",
    0x0157: "Huami (Amazfit/Xiaomi)",
    0x038F: "Xiaomi",
    0x0499: "Ruuvi",
    0x0059: "Nordic Semiconductor",
    0x000F: "Broadcom",
    0x0131: "Cypress",
    0x004F: "APT (Airoha)",
    0x022B: "Tile",
    0x0110: "Fitbit",
    0x0201: "GN Netcom (Jabra)",
    0x00C4: "LG Electronics",
    0x0001: "Nokia",
    0x0118: "Sony",
    0x03DA: "Logitech",
    0x0180: "Dexcom",
    0x0A8D: "Govee",
}

# First byte of Apple's 0x004C manufacturer payload -> what it advertises.
APPLE_BLE_TYPES = {
    0x02: "iBeacon",
    0x05: "AirDrop",
    0x07: "Proximity Pairing (AirPods/Beats)",
    0x09: "AirPlay target",
    0x0A: "AirPlay source",
    0x0B: "Watch nearby",
    0x0C: "Handoff",
    0x0D: "Wi-Fi settings",
    0x0E: "Hotspot",
    0x0F: "Wi-Fi join",
    0x10: "Nearby (iPhone/iPad)",
    0x12: "Find My (AirTag / offline finding)",
    0x16: "Find My",
}


def _apple_ble_hint(payload: bytes) -> str | None:
    if not payload:
        return None
    return APPLE_BLE_TYPES.get(payload[0])


def _ble_company_name(cid: int) -> str:
    return BLE_COMPANY_IDS.get(cid, f"0x{cid:04x}")


def collect_ble_scan(seconds: float = 6.0) -> dict[str, Any]:
    """Discover nearby BLE devices that are broadcasting advertisements.

    This uses the optional `bleak` package. It listens for advertising packets
    and reads the public advertisement fields (name, RSSI, manufacturer data,
    service UUIDs). It never pairs, connects, or writes, so no device shows a
    prompt and no person is notified — it is receive-oriented discovery of data
    the devices are already broadcasting to everyone in range.
    """
    result: dict[str, Any] = {"available": False, "supported": True, "devices": [], "error": None}
    try:
        from bleak import BleakScanner  # type: ignore
    except Exception:
        result["supported"] = False
        result["error"] = "bleak not installed (pip install bleak)"
        return result

    import asyncio

    async def _scan() -> dict[str, Any]:
        return await BleakScanner.discover(timeout=seconds, return_adv=True)

    try:
        found = asyncio.run(_scan())
    except Exception as exc:  # permission denied, adapter off, etc.
        result["error"] = str(exc)
        return result

    result["available"] = True
    devices = []
    for addr, pair in found.items():
        try:
            dev, adv = pair
        except (TypeError, ValueError):
            dev, adv = pair, None
        mfg = getattr(adv, "manufacturer_data", None) or {}
        companies = [_ble_company_name(cid) for cid in mfg]
        apple_hint = None
        if 0x004C in mfg:
            apple_hint = _apple_ble_hint(bytes(mfg[0x004C]))
        name = getattr(adv, "local_name", None) or getattr(dev, "name", None)
        rssi = getattr(adv, "rssi", None)
        if rssi in (127, None):  # 127 = CoreBluetooth "RSSI unavailable"
            rssi = None
        devices.append({
            "address": addr,
            "name": name,
            "rssi": rssi,
            "tx_power": getattr(adv, "tx_power", None),
            "companies": companies,
            "apple_type": apple_hint,
            "service_uuids": list(getattr(adv, "service_uuids", None) or []),
            "guess": _guess_ble_type(name, companies, apple_hint),
        })
    devices.sort(key=lambda d: (d["rssi"] if d["rssi"] is not None else -999), reverse=True)
    result["devices"] = devices
    result["named_count"] = sum(1 for d in devices if d["name"])
    return result


def _guess_ble_type(name: str | None, companies: list[str], apple_hint: str | None) -> str | None:
    blob = (name or "").lower()
    rules = [
        ("govee", "Govee sensor/light"),
        ("airtag", "Apple AirTag"),
        ("airpods", "AirPods"),
        ("beats", "Beats headphones"),
        ("tile", "Tile tracker"),
        ("ruuvi", "RuuviTag sensor"),
        ("flic", "Flic button"),
        ("mi ", "Xiaomi/Mi device"),
        ("amazfit", "Amazfit wearable"),
        ("fitbit", "Fitbit wearable"),
        ("garmin", "Garmin wearable"),
        ("bose", "Bose audio"),
        ("sony", "Sony audio"),
        ("jbl", "JBL speaker"),
        ("srs-", "Sony speaker"),
        ("sense", "Sensor"),
        ("thermo", "Thermometer/sensor"),
        ("scale", "Smart scale"),
        ("watch", "Smartwatch"),
        ("band", "Fitness band"),
        ("bulb", "Smart bulb"),
        ("lamp", "Smart light"),
        ("cam", "Camera"),
        ("lock", "Smart lock"),
        ("tv", "TV / media device"),
    ]
    for needle, label in rules:
        if needle in blob:
            return label
    if apple_hint:
        if "Find My" in apple_hint:
            return "Apple Find My tag/device"
        if "Proximity" in apple_hint:
            return "AirPods / Beats (nearby)"
        if "Nearby" in apple_hint:
            return "iPhone / iPad (nearby)"
        if "Watch" in apple_hint:
            return "Apple Watch (nearby)"
        return f"Apple device ({apple_hint})"
    if companies:
        known = [c for c in companies if not c.startswith("0x")]
        if known:
            return f"{known[0]} device"
    return None


# ---------------------------------------------------------------------------
# Wi-Fi / LAN session
# ---------------------------------------------------------------------------

def json_profiler(*data_types: str) -> dict[str, Any]:
    if sys.platform != "darwin":
        return {}
    cmd = ["system_profiler", *data_types, "-json"]
    out = run(cmd, timeout=25)
    if not out.strip():
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def wifi_from_system_profiler() -> dict[str, Any]:
    data = json_profiler("SPAirPortDataType")
    blocks = data.get("SPAirPortDataType") or []
    result: dict[str, Any] = {"raw_present": bool(blocks)}
    for block in blocks:
        software = block.get("spairport_software_information")
        if software:
            result["wifi_software"] = software
        for iface in block.get("spairport_airport_interfaces") or []:
            current = iface.get("spairport_current_network_information") or {}
            if not current and not iface.get("spairport_status_information"):
                continue
            parsed = {
                "interface": iface.get("_name"),
                "status": iface.get("spairport_status_information"),
                "supported_phy": iface.get("spairport_supported_phymodes"),
                "supported_channels": iface.get("spairport_supported_channels"),
                "ssid": current.get("_name"),
                "channel": current.get("spairport_network_channel"),
                "phymode": current.get("spairport_network_phymode"),
                "network_type": current.get("spairport_network_type"),
                "security": current.get("spairport_security_mode"),
                "signal_noise": current.get("spairport_signal_noise"),
                "country_code": current.get("spairport_network_country_code"),
                "other_local_networks": [
                    n.get("_name")
                    for n in (iface.get("spairport_airport_other_local_wireless_networks") or [])
                    if n.get("_name")
                ][:30],
            }
            result["interface"] = parsed
            return result
    return result


def ipconfig_summary(iface: str) -> dict[str, str]:
    out = run(["ipconfig", "getsummary", iface], timeout=5)
    info: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if " : " in line or ":" in line:
            if line.endswith("{"):
                continue
            parts = re.split(r"\s+:\s+|\s*:\s+", line, maxsplit=1)
            if len(parts) == 2 and parts[0] and not parts[0].startswith("}"):
                info[parts[0].strip()] = parts[1].strip().strip('"')
    return info


def ipconfig_packet(iface: str) -> dict[str, str]:
    out = run(["ipconfig", "getpacket", iface], timeout=5)
    info: dict[str, str] = {}
    for line in out.splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            info[k.strip()] = v.strip()
    return info


def networksetup_wifi(iface: str) -> dict[str, str]:
    info: dict[str, str] = {}
    ssid = run(["networksetup", "-getairportnetwork", iface], timeout=4).strip()
    if ssid:
        info["airport_network"] = ssid
    power = run(["networksetup", "-getairportpower", iface], timeout=4).strip()
    if power:
        info["airport_power"] = power
    details = run(["networksetup", "-getinfo", "Wi-Fi"], timeout=4)
    for line in details.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def wdutil_info() -> str:
    return run(["wdutil", "info"], timeout=8).strip()


def linux_wifi() -> dict[str, Any]:
    info: dict[str, Any] = {}
    if which("nmcli"):
        info["nmcli_dev"] = run(["nmcli", "-t", "-f", "GENERAL,WIFI-PROPERTIES,IP4,IP6", "dev", "show"], timeout=6)
        info["nmcli_wifi"] = run(["nmcli", "-f", "active,ssid,bssid,chan,rate,signal,security", "dev", "wifi"], timeout=6)
    if which("iw"):
        info["iw"] = run(["iw", "dev"], timeout=5)
    return info


def public_ip_info(timeout: float = 4.0) -> dict[str, Any]:
    urls = [
        "https://ipinfo.io/json",
        "https://ifconfig.me/all.json",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "network-inventory/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {"raw": raw.strip()}
                data["source"] = url
                return data
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            continue
    return {"error": "public IP lookup failed (offline or blocked)"}


def collect_wifi(ifaces: list[Interface], route: dict[str, str]) -> dict[str, Any]:
    port_map = macos_hardware_port_map() if sys.platform == "darwin" else {}
    lan = pick_lan_interface(ifaces)
    wifi_iface = lan.name if lan else None

    ns: dict[str, str] = {}
    dhcp: dict[str, str] = {}
    if sys.platform == "darwin" and wifi_iface:
        ns = networksetup_wifi(wifi_iface)
        dhcp = ipconfig_packet(wifi_iface)

    lan_gateway = None
    for candidate in (
        ns.get("Router"),
        dhcp.get("router"),
        dhcp.get("router (ip)"),
    ):
        if not candidate:
            continue
        cleaned = candidate.strip("{}[] ")
        if looks_like_ip(cleaned.split()[0] if cleaned else ""):
            lan_gateway = cleaned.split()[0]
            break

    vpn = None
    route_iface = route.get("interface") or ""
    if route_iface and is_tunnel_name(route_iface):
        vpn = {
            "interface": route_iface,
            "gateway": route.get("gateway"),
            "note": "Default route is a VPN/tunnel; LAN scan uses Wi-Fi/Ethernet instead.",
        }

    info: dict[str, Any] = {
        "active_interface": wifi_iface,
        "active_interface_kind": (lan.kind if lan else None) or port_map.get(wifi_iface or ""),
        "gateway": lan_gateway or (None if vpn else route.get("gateway")),
        "active_ipv4": lan.ipv4 if lan else [],
        "active_ipv6": lan.ipv6 if lan else [],
        "active_mac": lan.mac if lan else None,
        "active_netmasks": lan.netmasks if lan else [],
        "vpn": vpn,
        "default_route": route,
    }
    if sys.platform == "darwin" and wifi_iface:
        info["system_profiler"] = wifi_from_system_profiler()
        info["networksetup"] = ns
        info["ipconfig_summary"] = ipconfig_summary(wifi_iface)
        info["dhcp_packet"] = dhcp
        wd = wdutil_info()
        if wd:
            info["wdutil"] = wd
    elif sys.platform.startswith("linux"):
        info["linux"] = linux_wifi()

    subnet = None
    if lan and lan.ipv4 and lan.netmasks:
        try:
            subnet = str(ipaddress.IPv4Interface(f"{lan.ipv4[0]}/{lan.netmasks[0]}").network)
        except ValueError:
            pass
    elif lan and lan.ipv4:
        try:
            subnet = str(ipaddress.IPv4Interface(f"{lan.ipv4[0]}/24").network)
        except ValueError:
            pass
    info["subnet"] = subnet
    return info


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def target_network(subnet: str, self_ip: str) -> ipaddress.IPv4Network:
    net = ipaddress.IPv4Network(subnet, strict=False)
    if net.prefixlen < 24:
        # Do not walk a /16. Stay in the host's /24.
        host = ipaddress.IPv4Address(self_ip)
        net = ipaddress.IPv4Network(f"{host}/24", strict=False)
    return net


def ping_one(ip: str) -> bool:
    if sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", "200", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    code, _, _ = run_ok(cmd, timeout=2.5)
    return code == 0


def udp_nudge(network: ipaddress.IPv4Network, bind_ip: str | None = None) -> None:
    """Send a tiny UDP packet so the kernel fills the ARP table on the LAN iface."""
    payload = b"\x00"
    for host in network.hosts():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            if bind_ip:
                try:
                    sock.bind((bind_ip, 0))
                except OSError:
                    pass
            try:
                sock.sendto(payload, (str(host), 5353))
            finally:
                sock.close()
        except OSError:
            continue


def parse_arp() -> list[tuple[str, str | None, str | None, str | None]]:
    """Returns (ip, mac, iface, name)."""
    rows = []
    out = run(["arp", "-an"], timeout=5)
    # macOS: hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    pat = re.compile(
        r"^(?P<name>\S+)\s+\((?P<ip>[0-9.]+)\)\s+at\s+(?P<mac>\S+)(?:\s+on\s+(?P<iface>\S+))?"
    )
    if out:
        for line in out.splitlines():
            m = pat.search(line.strip())
            if not m:
                continue
            ip = m.group("ip")
            mac = norm_mac(m.group("mac"))
            if not mac:
                continue
            if not is_unicast_ipv4(ip) or not is_unicast_mac(mac):
                continue
            name = m.group("name")
            if name == "?":
                name = None
            rows.append((ip, mac, m.group("iface"), name))
        if rows:
            return rows
    out = run(["ip", "neigh"], timeout=5)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].count(".") == 3:
            ip = parts[0]
            mac = None
            if "lladdr" in parts:
                mac = norm_mac(parts[parts.index("lladdr") + 1])
            if not mac or not is_unicast_ipv4(ip) or not is_unicast_mac(mac):
                continue
            rows.append((ip, mac, parts[2] if len(parts) > 2 else None, None))
    return rows


def parse_ndp() -> list[tuple[str, str | None, str | None]]:
    rows = []
    out = run(["ndp", "-an"], timeout=5)
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and ":" in parts[0]:
            ip = parts[0].split("%")[0]
            mac = norm_mac(parts[1]) if parts[1] != "(incomplete)" else None
            iface = parts[2] if len(parts) > 2 else None
            rows.append((ip, mac, iface))
    if rows:
        return rows
    out = run(["ip", "-6", "neigh"], timeout=5)
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0].split("%")[0]
        mac = None
        if "lladdr" in parts:
            mac = norm_mac(parts[parts.index("lladdr") + 1])
        rows.append((ip, mac, None))
    return rows


def reverse_name(ip: str, timeout: float = 0.6) -> str | None:
    socket.setdefaulttimeout(timeout)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


# ---------------------------------------------------------------------------
# mDNS
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raw = raw[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def decode_name(buf: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 10 or offset >= len(buf):
        return "", offset
    labels = []
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            suffix, _ = decode_name(buf, ptr, depth + 1)
            if suffix:
                labels.append(suffix)
            offset += 2
            break
        offset += 1
        labels.append(buf[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    name = ".".join(labels)
    return name, offset


def build_mdns_query(names: list[str]) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x0000, len(names), 0, 0, 0)
    body = bytearray()
    for name in names:
        body.extend(encode_name(name))
        body.extend(struct.pack("!HH", 12, 0x8001))  # PTR, IN + QU
    return header + bytes(body)


def parse_mdns_packet(buf: bytes) -> list[dict[str, Any]]:
    if len(buf) < 12:
        return []
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    offset = 12
    records: list[dict[str, Any]] = []

    def skip_questions(n: int) -> int:
        off = offset
        for _ in range(n):
            _, off = decode_name(buf, off)
            off += 4
            if off > len(buf):
                return off
        return off

    offset = skip_questions(qd)
    total = an + ns + ar
    for _ in range(total):
        if offset + 10 > len(buf):
            break
        name, offset = decode_name(buf, offset)
        if offset + 10 > len(buf):
            break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[offset : offset + 10])
        offset += 10
        rdata = buf[offset : offset + rdlen]
        offset += rdlen
        rec: dict[str, Any] = {"name": name, "type": rtype, "ttl": ttl}
        try:
            if rtype == 1 and len(rdata) >= 4:  # A
                rec["a"] = socket.inet_ntoa(rdata[:4])
            elif rtype == 28 and len(rdata) >= 16:  # AAAA
                rec["aaaa"] = socket.inet_ntop(socket.AF_INET6, rdata[:16])
            elif rtype == 12:  # PTR
                ptr, _ = decode_name(buf, offset - rdlen)
                rec["ptr"] = ptr
            elif rtype == 33 and len(rdata) >= 6:  # SRV
                prio, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = decode_name(rdata + buf, 6)  # may fail; fallback below
                # decode relative to original packet
                tname, _ = decode_name(buf, offset - rdlen + 6)
                rec["srv"] = {"port": port, "target": tname, "priority": prio, "weight": weight}
            elif rtype == 16:  # TXT
                txts = {}
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    i += 1
                    chunk = rdata[i : i + ln].decode("utf-8", errors="replace")
                    i += ln
                    if "=" in chunk:
                        k, v = chunk.split("=", 1)
                        txts[k] = v
                    elif chunk:
                        txts[chunk] = ""
                rec["txt"] = txts
        except (OSError, struct.error, ValueError):
            pass
        records.append(rec)
    return records


def _bind_lan_udp(lan_ip: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass
    sock.setblocking(False)
    if lan_ip:
        sock.bind((lan_ip, 0))
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip))
        except OSError:
            pass
    else:
        sock.bind(("", 0))
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 255))
    except OSError:
        pass
    return sock


def mdns_browse(seconds: float = 3.0, lan_ip: str | None = None) -> list[dict[str, Any]]:
    try:
        sock = _bind_lan_udp(lan_ip)
    except OSError:
        return []
    try:
        sock.sendto(build_mdns_query(COMMON_MDNS_SERVICES), ("224.0.0.251", 5353))
        sock.sendto(build_mdns_query_qm(COMMON_MDNS_SERVICES[:12]), ("224.0.0.251", 5353))
    except OSError:
        sock.close()
        return []

    records: list[dict[str, Any]] = []
    deadline = time.time() + seconds
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ready, _, _ = select.select([sock], [], [], min(0.4, remaining))
        if not ready:
            continue
        try:
            data, _addr = sock.recvfrom(65535)
        except OSError:
            break
        records.extend(parse_mdns_packet(data))
    sock.close()
    return records


def build_mdns_query_qm(names: list[str]) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x0000, len(names), 0, 0, 0)
    body = bytearray()
    for name in names:
        body.extend(encode_name(name))
        body.extend(struct.pack("!HH", 12, 0x0001))
    return header + bytes(body)


def mdns_reverse(ips: list[str], seconds: float = 1.5, lan_ip: str | None = None) -> dict[str, str]:
    names = []
    for ip in ips:
        try:
            parts = str(ipaddress.IPv4Address(ip)).split(".")
        except ipaddress.AddressValueError:
            continue
        names.append(".".join(reversed(parts)) + ".in-addr.arpa")
    if not names:
        return {}
    try:
        sock = _bind_lan_udp(lan_ip)
        sock.sendto(build_mdns_query(names[:64]), ("224.0.0.251", 5353))
    except OSError:
        return {}
    mapping: dict[str, str] = {}
    deadline = time.time() + seconds
    while time.time() < deadline:
        ready, _, _ = select.select([sock], [], [], 0.3)
        if not ready:
            continue
        try:
            data, _ = sock.recvfrom(65535)
        except OSError:
            break
        for rec in parse_mdns_packet(data):
            if rec.get("ptr") and rec.get("name", "").endswith(".in-addr.arpa"):
                labels = rec["name"].replace(".in-addr.arpa", "").split(".")
                if len(labels) == 4:
                    ip = ".".join(reversed(labels))
                    mapping[ip] = rec["ptr"].rstrip(".")
            if rec.get("a"):
                mapping[rec["a"]] = rec.get("name", "").rstrip(".")
    sock.close()
    return mapping


# ---------------------------------------------------------------------------
# NetBIOS name (UDP 137) — identification only
# ---------------------------------------------------------------------------

def netbios_name(ip: str, timeout: float = 0.6) -> str | None:
    # NBNS name query for '*'
    payload = bytes.fromhex(
        "820000000001000000000000"
        "20434b414141414141414141414141414141414141414141414141414141414141"
        "0000210001"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except OSError:
        return None
    if len(data) < 57:
        return None
    # First name at offset 57 in many responses; scan printable
    try:
        names_count = data[56]
    except IndexError:
        return None
    offset = 57
    for _ in range(min(names_count, 8)):
        chunk = data[offset : offset + 15]
        if not chunk:
            break
        name = chunk.decode("ascii", errors="ignore").strip()
        if name:
            return name
        offset += 18
    return None


# ---------------------------------------------------------------------------
# SSDP / UPnP discovery (device model, manufacturer, friendly name)
# ---------------------------------------------------------------------------

SSDP_ADDR = ("239.255.255.250", 1900)


def ssdp_discover(seconds: float = 3.0, lan_ip: str | None = None) -> dict[str, dict[str, str]]:
    """M-SEARCH the LAN; return {ip: {header: value, ...}} incl. LOCATION."""
    targets = ("ssdp:all", "upnp:rootdevice")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        if lan_ip:
            sock.bind((lan_ip, 0))
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip))
            except OSError:
                pass
        else:
            sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 2))
    except OSError:
        return {}

    for st in targets:
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            f"ST: {st}\r\n\r\n"
        ).encode()
        try:
            sock.sendto(msg, SSDP_ADDR)
        except OSError:
            pass

    results: dict[str, dict[str, str]] = {}
    deadline = time.time() + seconds
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ready, _, _ = select.select([sock], [], [], min(0.4, remaining))
        if not ready:
            continue
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            break
        ip = addr[0]
        headers: dict[str, str] = {}
        for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().upper()] = v.strip()
        if headers:
            results.setdefault(ip, {}).update(headers)
    sock.close()
    return results


def fetch_upnp_description(location: str, timeout: float = 2.5) -> dict[str, str]:
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "network-inventory/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml = resp.read(8192).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {}
    fields = {}
    for tag in (
        "friendlyName",
        "manufacturer",
        "modelName",
        "modelNumber",
        "modelDescription",
        "serialNumber",
        "deviceType",
    ):
        m = re.search(rf"<{tag}>([^<]+)</{tag}>", xml, re.I)
        if m:
            val = re.sub(r"\s+", " ", m.group(1)).strip()
            if val:
                fields[tag] = val[:120]
    return fields


def collect_ssdp(hosts: dict[str, "Host"], net: ipaddress.IPv4Network, lan_ip: str | None, seconds: float) -> None:
    raw = ssdp_discover(seconds=seconds, lan_ip=lan_ip)
    locations: dict[str, str] = {}
    for ip, headers in raw.items():
        if not is_unicast_ipv4(ip) or ipaddress.IPv4Address(ip) not in net:
            continue
        server = headers.get("SERVER")
        merge_host(hosts, ip, source=["ssdp"])
        host = hosts[ip]
        if server:
            host.ssdp.setdefault("server", server)
        if headers.get("LOCATION"):
            locations[ip] = headers["LOCATION"]

    def resolve(item: tuple[str, str]) -> None:
        ip, location = item
        desc = fetch_upnp_description(location)
        if not desc:
            return
        host = hosts.get(ip)
        if host is None:
            return
        for k, v in desc.items():
            host.ssdp[k] = v
        friendly = desc.get("friendlyName")
        model = desc.get("modelName")
        if friendly and friendly not in host.names:
            host.names.insert(0, friendly)
        if model and not host.model:
            host.model = " ".join(x for x in (desc.get("manufacturer"), model, desc.get("modelNumber")) if x)

    if locations:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(resolve, locations.items()))


def apple_model_name(code: str | None) -> str | None:
    if not code:
        return None
    code = code.strip()
    if code in APPLE_MODELS:
        return APPLE_MODELS[code]
    for prefix, name in APPLE_MODELS.items():
        if code.startswith(prefix):
            return name
    return None


# ---------------------------------------------------------------------------
# OS guess from TTL
# ---------------------------------------------------------------------------

def ping_ttl(ip: str) -> int | None:
    if sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-t", "1", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    code, out, _ = run_ok(cmd, timeout=2.5)
    if code != 0:
        return None
    m = re.search(r"ttl[=\s](\d+)", out, re.I)
    return int(m.group(1)) if m else None


def os_from_ttl(ttl: int | None) -> str | None:
    if ttl is None:
        return None
    # Guess the sender's initial TTL. Common initial values: 255 (net gear),
    # 128 (Windows), 64 (unix/apple/android), 32 (some IoT/embedded stacks).
    for base, label in ((32, "IoT / embedded stack"),
                        (64, "Linux / macOS / iOS / Android"),
                        (128, "Windows"),
                        (255, "network gear / router / printer")):
        if ttl <= base:
            hops = base - ttl
            if hops > 8:
                # More hops than any LAN path — initial TTL is nonstandard.
                return f"TTL {ttl} (nonstandard initial TTL — device type unclear)"
            hop_txt = "same subnet" if hops == 0 else f"~{hops} hop{'s' if hops != 1 else ''}"
            return f"{label} (TTL {ttl}, {hop_txt})"
    return f"TTL {ttl}"


# ---------------------------------------------------------------------------
# Defensive exposure assessment (identification only — no exploitation)
# ---------------------------------------------------------------------------

def assess_risks(host: "Host") -> list[str]:
    risks = list(host.risks)
    for port, banner in host.banners.items():
        low = banner.lower()
        if "http" in low and "server" in low and any(
            s in low for s in ("boa", "goahead", "lighttpd/1.4.1", "micro_httpd")
        ):
            risks.append(f"port {port}: embedded web server often shipped with default creds")
        if re.search(r"openssh_[0-6]\.", low):
            risks.append(f"port {port}: very old OpenSSH banner — likely unpatched")
    if any(p.startswith(("23/", "2323/")) for p in host.open_ports):
        pass  # already flagged in probe
    if host.is_gateway and any(p.startswith(("80/", "8080/")) for p in host.open_ports):
        risks.append("router admin page reachable over plain HTTP on the LAN")
    # de-dupe, keep order
    seen: set[str] = set()
    out = []
    for r in risks:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Light service identification
# ---------------------------------------------------------------------------

def probe_port(ip: str, port: int, timeout: float = 0.45) -> tuple[bool, str | None]:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return False, None
    banner = None
    try:
        sock.settimeout(timeout)
        if port in {80, 8080, 8008, 5000, 8443, 9000, 49152}:
            sock.sendall(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: network-inventory\r\n\r\n".encode()
            )
            data = sock.recv(2048)
            text = data.decode("latin-1", errors="replace")
            server = None
            title = None
            m = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
            if m:
                server = m.group(1).strip()
            m = re.search(r"<title[^>]*>([^<]+)</title>", text, re.I)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            status = text.split("\r\n", 1)[0][:40]
            banner = " | ".join(b for b in (title, server, status) if b) or None
        elif port in {443, 8009, 8883}:
            banner = "tls (encrypted)"
        elif port in {22, 21, 23, 2323, 25, 110, 143, 3306, 5432, 6379}:
            data = sock.recv(160)
            banner = data.decode("utf-8", errors="replace").strip()[:120] or None
        else:
            try:
                data = sock.recv(96)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()[:120]
            except OSError:
                banner = None
    except OSError:
        banner = None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True, banner


def probe_host(ip: str, timeout: float) -> tuple[list[str], dict[str, str], list[str]]:
    open_ports: list[str] = []
    banners: dict[str, str] = {}
    risks: list[str] = []
    for port, label, risk in IDENT_PORTS:
        ok, banner = probe_port(ip, port, timeout=timeout)
        if ok:
            open_ports.append(f"{port}/{label}")
            if banner:
                banners[str(port)] = banner
            if risk:
                risks.append(f"{label} open ({port}) — {risk}")
    return open_ports, banners, risks


def gateway_http_title(ip: str, timeout: float = 2.0) -> str | None:
    for scheme in ("http",):
        try:
            req = urllib.request.Request(
                f"{scheme}://{ip}/",
                headers={"User-Agent": "network-inventory/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(4096).decode("utf-8", errors="replace")
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                title = None
                m = re.search(r"<title[^>]*>([^<]+)</title>", raw, re.I)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()
                server = hdrs.get("server")
                bits = [b for b in (title, server, f"status {resp.status}") if b]
                return " | ".join(bits)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    return None


# ---------------------------------------------------------------------------
# OUI / vendor
# ---------------------------------------------------------------------------

_manuf_cache: dict[str, str] | None = None


def load_local_manuf() -> dict[str, str]:
    global _manuf_cache
    if _manuf_cache is not None:
        return _manuf_cache
    paths = [
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
        os.path.expanduser("~/.cache/network_inventory/manuf"),
    ]
    mapping: dict[str, str] = {}
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = re.split(r"\s+", line, maxsplit=2)
                    if len(parts) < 2:
                        continue
                    prefix = parts[0].replace(":", "").replace("-", "").upper()
                    prefix = prefix.split("/")[0]
                    if len(prefix) >= 6 and all(c in "0123456789ABCDEF" for c in prefix[:6]):
                        mapping[prefix[:6]] = parts[-1] if len(parts) > 2 else parts[1]
            if mapping:
                break
        except OSError:
            continue
    _manuf_cache = mapping
    return mapping


_mvl_lookup: Any = None
_mvl_tried = False


def _optional_mac_vendor(mac: str) -> str | None:
    """Use the optional `mac-vendor-lookup` package (full IEEE OUI DB) if installed."""
    global _mvl_lookup, _mvl_tried
    if not _mvl_tried:
        _mvl_tried = True
        try:
            from mac_vendor_lookup import MacLookup  # type: ignore

            _mvl_lookup = MacLookup()
        except Exception:
            _mvl_lookup = None
    if _mvl_lookup is None:
        return None
    try:
        return _mvl_lookup.lookup(mac)
    except Exception:
        return None


def vendor_offline(mac: str) -> str | None:
    n = norm_mac(mac)
    if not n:
        return None
    # locally administered / randomized bit takes priority — the OUI is meaningless.
    try:
        first = int(n.split(":")[0], 16)
        if first & 0x02:
            return "locally administered MAC (often randomized / private Wi-Fi)"
    except ValueError:
        pass
    if any(n.upper().startswith(p) for p in APPLE_OUI_HINTS):
        return "Apple"
    p24 = mac_prefix24(n)
    manuf = load_local_manuf()
    if p24 in manuf:
        return manuf[p24]
    if p24 in OUI_FALLBACK:
        return OUI_FALLBACK[p24]
    lib = _optional_mac_vendor(n)
    if lib:
        return lib
    return None


def vendor_online(mac: str, timeout: float = 3.0) -> str | None:
    n = norm_mac(mac)
    if not n:
        return None
    url = f"https://api.macvendors.com/{n}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "network-inventory/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace").strip()
            if text and "not found" not in text.lower() and "<" not in text:
                return text[:80]
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def guess_type(host: Host) -> str:
    # Advertised identity (device chose to announce this) — trustworthy for TV/IoT hints.
    adv_blob = " ".join(
        [
            " ".join(host.names),
            host.model or "",
            " ".join(host.ssdp.values()),
            " ".join(host.mdns_services),
        ]
    ).lower()
    # Everything, including port labels — used for weaker keyword rules.
    blob = " ".join(
        [
            adv_blob,
            " ".join(host.open_ports),
            host.vendor or "",
            " ".join(host.txt.values()),
        ]
    ).lower()

    for needle, label in SSDP_HINTS:
        if needle in adv_blob:
            return label

    rules = [
        ("samsung", "Samsung TV / device"),
        ("ps4", "PlayStation 4"),
        ("playstation", "PlayStation"),
        ("living-room", "Living-room media device"),
        ("living room", "Living-room media device"),
        ("iphone", "iPhone"),
        ("ipad", "iPad"),
        ("watch", "Apple Watch"),
        ("macbook", "Mac laptop"),
        ("imac", "iMac"),
        ("macmini", "Mac mini"),
        ("mac studio", "Mac Studio"),
        ("appletv", "Apple TV"),
        ("apple tv", "Apple TV"),
        ("homepod", "HomePod"),
        ("airplay", "AirPlay speaker / Apple TV"),
        ("companion-link", "Apple device (Continuity)"),
        ("androidtv", "Android TV"),
        ("googlecast", "Chromecast / Google Cast"),
        ("chromecast", "Chromecast"),
        ("sonos", "Sonos"),
        ("spotify-connect", "Spotify Connect speaker"),
        ("printer", "Printer"),
        ("_ipp._tcp", "Printer"),
        ("jetdirect", "Printer"),
        ("scanner", "Scanner"),
        ("plex", "Plex media server"),
        ("synology", "NAS (Synology)"),
        ("_adisk._tcp", "NAS / Time Machine"),
        ("_smb._tcp", "File server / NAS"),
        ("raspberry", "Raspberry Pi"),
        ("esp32", "ESP32 / IoT"),
        ("esphome", "ESPHome device"),
        ("hue", "Philips Hue"),
        ("matter", "Matter device"),
        ("homekit", "HomeKit accessory"),
        ("_hap._tcp", "HomeKit accessory"),
        ("echo", "Amazon Echo"),
        ("kindle", "Kindle / Amazon"),
        ("roku", "Roku"),
        ("firetv", "Fire TV"),
        ("xbox", "Xbox"),
        ("playstation", "PlayStation"),
        ("nintendo", "Nintendo"),
        ("ios-lockdown", "iOS / iPadOS device"),
        ("windows", "Windows PC"),
        ("smb", "Windows / SMB host"),
    ]
    for needle, label in rules:
        if needle in blob:
            return label
    if host.is_gateway:
        return "Router / gateway"
    if host.model:
        return host.model
    # Vendor-based guesses for silent, MAC-only hosts (Wi-Fi module / chip makers).
    vlow = (host.vendor or "").lower()
    for needle, label in VENDOR_HINTS:
        if needle in vlow:
            return label
    if host.vendor and "randomized" not in host.vendor and "administered" not in host.vendor:
        return f"Host ({host.vendor})"
    if host.os_guess and host.os_guess[0].isalpha() and not host.os_guess.startswith("TTL"):
        return f"Unidentified {host.os_guess.split(' (')[0]} host"
    return "Unknown host"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def merge_host(hosts: dict[str, Host], ip: str, **kwargs: Any) -> Host:
    host = hosts.get(ip)
    if host is None:
        host = Host(ip=ip)
        hosts[ip] = host
    if kwargs.get("mac") and not host.mac:
        host.mac = norm_mac(kwargs["mac"])
    if kwargs.get("vendor") and not host.vendor:
        host.vendor = kwargs["vendor"]
    for name in kwargs.get("names") or []:
        if name and name not in host.names:
            host.names.append(name)
    for src in kwargs.get("source") or []:
        if src not in host.source:
            host.source.append(src)
    for svc in kwargs.get("mdns_services") or []:
        if svc and svc not in host.mdns_services:
            host.mdns_services.append(svc)
    if kwargs.get("txt"):
        host.txt.update({k: v for k, v in kwargs["txt"].items() if v})
    for v6 in kwargs.get("ipv6") or []:
        if v6 not in host.ipv6:
            host.ipv6.append(v6)
    if kwargs.get("is_self"):
        host.is_self = True
    if kwargs.get("is_gateway"):
        host.is_gateway = True
    return host


def apply_mdns(hosts: dict[str, Host], records: list[dict[str, Any]]) -> None:
    ptr_to_ip: dict[str, str] = {}
    name_to_ip: dict[str, str] = {}
    for rec in records:
        if rec.get("a"):
            name_to_ip[rec["name"].rstrip(".").lower()] = rec["a"]
            merge_host(hosts, rec["a"], names=[rec["name"].rstrip(".")], source=["mdns-a"])
        if rec.get("aaaa"):
            # stash on matching A name later
            pass
    for rec in records:
        if rec.get("ptr"):
            instance = rec["ptr"].rstrip(".")
            svc = rec["name"].rstrip(".")
            ip = name_to_ip.get(instance.lower())
            # instance often "Name._airplay._tcp.local"
            short = instance.split(".")[0]
            if ip:
                merge_host(
                    hosts,
                    ip,
                    names=[short, instance],
                    mdns_services=[svc],
                    source=["mdns-ptr"],
                )
                ptr_to_ip[instance.lower()] = ip
        if rec.get("srv"):
            target = rec["srv"].get("target", "").rstrip(".").lower()
            ip = name_to_ip.get(target) or name_to_ip.get(rec["name"].rstrip(".").lower())
            if ip:
                merge_host(
                    hosts,
                    ip,
                    names=[rec["name"].split(".")[0]],
                    source=["mdns-srv"],
                )
        if rec.get("txt"):
            ip = name_to_ip.get(rec["name"].rstrip(".").lower())
            if ip:
                merge_host(hosts, ip, txt=rec["txt"], source=["mdns-txt"])

    # TXT / PTR records whose A record arrived under a different name
    for rec in records:
        if not rec.get("ptr"):
            continue
        instance = rec["ptr"].rstrip(".")
        ip = ptr_to_ip.get(instance.lower()) or name_to_ip.get(instance.lower())
        if ip:
            merge_host(hosts, ip, mdns_services=[rec["name"].rstrip(".")], names=[instance.split(".")[0]])


def discover_hosts(
    subnet: str,
    self_ips: set[str],
    gateway: str | None,
    fast: bool,
    probe: bool,
    probe_timeout: float,
    mdns_seconds: float,
    online_oui: bool,
    lan_ip: str | None = None,
    lan_iface: str | None = None,
) -> list[Host]:
    self_ip = lan_ip or (next(iter(self_ips)) if self_ips else None)
    net = target_network(subnet, self_ip or str(ipaddress.IPv4Network(subnet).network_address + 1))
    hosts: dict[str, Host] = {}

    print(_c(Style.DIM, f"  Discovering {net} on {lan_iface or 'default'} (ARP + ping + mDNS)…"))
    udp_nudge(net, bind_ip=lan_ip)

    ping_ips = [str(h) for h in net.hosts()]
    if fast:
        ping_ips = [ip for ip in ping_ips if ip.endswith(".1") or ip.endswith(".254") or ip in self_ips]
        if gateway:
            ping_ips.append(gateway)
        ping_ips = list(dict.fromkeys(ping_ips))

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        ping_hits = dict(zip(ping_ips, pool.map(ping_one, ping_ips)))
    alive = {ip for ip, ok in ping_hits.items() if ok}

    time.sleep(0.4)
    for ip, mac, iface, name in parse_arp():
        try:
            addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        if addr not in net and ip not in self_ips:
            continue
        if lan_iface and iface and iface != lan_iface:
            continue
        names = [name] if name else []
        merge_host(
            hosts,
            ip,
            mac=mac,
            names=names,
            source=["arp"],
            is_self=ip in self_ips,
            is_gateway=(ip == gateway),
        )

    for ip in self_ips:
        if is_unicast_ipv4(ip):
            merge_host(hosts, ip, source=["self"], is_self=True)
    if gateway and is_unicast_ipv4(gateway):
        merge_host(hosts, gateway, source=["route"], is_gateway=True)
        alive.add(gateway)

    # IPv6 neighbors: attach MAC to IPv4 twin when possible
    mac_to_v6: dict[str, list[str]] = defaultdict(list)
    for ip6, mac, _iface in parse_ndp():
        if mac:
            mac_to_v6[mac].append(ip6)
    for host in hosts.values():
        if host.mac and host.mac in mac_to_v6:
            for v6 in mac_to_v6[host.mac]:
                if v6 not in host.ipv6:
                    host.ipv6.append(v6)

    print(_c(Style.DIM, f"  Browsing Bonjour/mDNS for {mdns_seconds:.1f}s…"))
    records = mdns_browse(seconds=mdns_seconds, lan_ip=lan_ip)
    apply_mdns(hosts, records)

    print(_c(Style.DIM, f"  Searching SSDP/UPnP for {mdns_seconds:.1f}s (device models)…"))
    collect_ssdp(hosts, net, lan_ip, seconds=mdns_seconds)

    # Drop mDNS A records that are off-subnet (e.g. VPN / public)
    off_subnet = [
        ip
        for ip in list(hosts)
        if ip not in self_ips
        and not hosts[ip].is_gateway
        and not hosts[ip].is_self
        and (not is_unicast_ipv4(ip) or ipaddress.IPv4Address(ip) not in net)
    ]
    for ip in off_subnet:
        del hosts[ip]

    ips = list(hosts.keys())
    mdns_rev = mdns_reverse(ips, seconds=1.2 if not fast else 0.6, lan_ip=lan_ip)
    for ip, name in mdns_rev.items():
        if ip in hosts or (is_unicast_ipv4(ip) and ipaddress.IPv4Address(ip) in net):
            merge_host(hosts, ip, names=[name], source=["mdns-reverse"])

    def enrich_name(ip: str) -> None:
        n = reverse_name(ip, timeout=0.5)
        if n:
            merge_host(hosts, ip, names=[n], source=["ptr"])
        if not fast:
            nb = netbios_name(ip)
            if nb:
                merge_host(hosts, ip, names=[nb], source=["netbios"])

    print(_c(Style.DIM, "  Resolving names…"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(enrich_name, ips))

    # Vendors
    print(_c(Style.DIM, "  Looking up MAC vendors…"))
    unique_macs = {h.mac: h for h in hosts.values() if h.mac}
    prefix_vendor: dict[str, str] = {}
    for mac, host in unique_macs.items():
        off = vendor_offline(mac)
        if off:
            prefix_vendor[mac_prefix24(mac)] = off
            host.vendor = off
    if online_oui:
        seen_prefix: set[str] = set()
        for mac, host in unique_macs.items():
            if host.vendor and "randomized" not in (host.vendor or ""):
                continue
            p = mac_prefix24(mac)
            if p in seen_prefix:
                host.vendor = host.vendor or prefix_vendor.get(p)
                continue
            seen_prefix.add(p)
            online = vendor_online(mac)
            if online:
                prefix_vendor[p] = online
                host.vendor = online
            time.sleep(0.25)
        for host in hosts.values():
            if host.mac and not host.vendor:
                host.vendor = prefix_vendor.get(mac_prefix24(host.mac))

    if probe:
        print(_c(Style.DIM, "  Identifying common services (connect-only, no exploits)…"))
        def do_probe(ip: str) -> None:
            ports, banners, risks = probe_host(ip, timeout=probe_timeout)
            host = hosts[ip]
            host.open_ports = ports
            host.banners = banners
            host.risks = risks
            host.ttl = ping_ttl(ip)
            host.os_guess = os_from_ttl(host.ttl)

        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            list(pool.map(do_probe, list(hosts.keys())))

        if gateway and gateway in hosts:
            title = gateway_http_title(gateway)
            if title:
                hosts[gateway].banners["http"] = title
                hosts[gateway].txt.setdefault("gateway_http", title)

    for host in hosts.values():
        # de-dupe names
        seen = set()
        clean = []
        for n in host.names:
            key = n.lower().rstrip(".")
            if key in seen or key == host.ip:
                continue
            seen.add(key)
            clean.append(n.rstrip("."))
        host.names = clean
        # Resolve device model from mDNS device-info TXT / SSDP
        if not host.model:
            code = host.txt.get("model") or host.txt.get("am")
            friendly = apple_model_name(code)
            if friendly:
                host.model = friendly
            elif code and len(code) <= 40:
                host.model = code
        host.risks = assess_risks(host)
        host.guessed_type = guess_type(host)

    def keep(h: Host) -> bool:
        if h.is_self or h.is_gateway:
            return True
        if not is_unicast_ipv4(h.ip):
            return False
        if h.mac and is_unicast_mac(h.mac):
            return True
        if h.names or h.mdns_services or h.open_ports:
            return True
        if h.ip in alive:
            return True
        return False

    kept = [h for h in hosts.values() if keep(h)]

    # Sort: self, gateway, then IP
    def sort_key(h: Host) -> tuple[int, int]:
        try:
            n = int(ipaddress.IPv4Address(h.ip))
        except ipaddress.AddressValueError:
            n = 0
        pri = 0 if h.is_self else 1 if h.is_gateway else 2
        return pri, n

    return sorted(kept, key=sort_key)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def summarize_wifi(wifi: dict[str, Any]) -> dict[str, Any]:
    sp = ((wifi.get("system_profiler") or {}).get("interface")) or {}
    ns = wifi.get("networksetup") or {}
    summary = wifi.get("ipconfig_summary") or {}
    dhcp = wifi.get("dhcp_packet") or {}
    ssid = first_nonempty(
        sp.get("ssid"),
        (ns.get("airport_network") or "").replace("Current Wi-Fi Network: ", ""),
        summary.get("SSID"),
    )
    return {
        "ssid": ssid,
        "interface": wifi.get("active_interface"),
        "kind": wifi.get("active_interface_kind"),
        "ipv4": wifi.get("active_ipv4"),
        "ipv6": wifi.get("active_ipv6"),
        "mac": wifi.get("active_mac"),
        "subnet": wifi.get("subnet"),
        "gateway": wifi.get("gateway"),
        "channel": sp.get("channel"),
        "phymode": pretty_apple(sp.get("phymode")),
        "security": pretty_apple(sp.get("security")),
        "signal_noise": sp.get("signal_noise"),
        "country": sp.get("country_code"),
        "dhcp_server": dhcp.get("server_identifier") or summary.get("ServerIdentifier"),
        "router_opt": dhcp.get("router"),
        "domain_name": dhcp.get("domain_name"),
        "lease_time": dhcp.get("lease_time") or dhcp.get("ip_lease_start"),
        "networksetup": ns,
        "other_local_ssids": sp.get("other_local_networks") or [],
        "vpn": wifi.get("vpn"),
        "default_route": wifi.get("default_route"),
    }


def print_device(device: dict[str, Any]) -> None:
    heading("This device")
    kv("Collected", device.get("collected_at"))
    kv("User", device.get("username"))
    kv("Home", device.get("home"))
    names = device.get("macos_names") or {}
    kv("Computer name", names.get("ComputerName"))
    kv("Local hostname", names.get("LocalHostName"))
    kv("Bonjour / DNS hostname", names.get("HostName") or device.get("hostname_platform"))
    kv("FQDN", device.get("fqdn"))
    sw = device.get("sw_vers") or {}
    kv("macOS", " ".join(x for x in [sw.get("ProductName"), sw.get("ProductVersion"), sw.get("BuildVersion")] if x) or None)
    uname = device.get("uname") or {}
    kv("Kernel", f"{uname.get('system')} {uname.get('release')} ({uname.get('machine')})")
    ctl = device.get("sysctl") or {}
    kv("Model ID", ctl.get("hw.model"))
    ioreg = device.get("ioreg") or {}
    kv("Serial", ioreg.get("serial"))
    kv("Hardware UUID", ioreg.get("hardware_uuid"))
    kv("CPU", ctl.get("machdep.cpu.brand_string"))
    kv("CPUs", f"physical={ctl.get('hw.physicalcpu')} logical={ctl.get('hw.logicalcpu')}" if ctl.get("hw.logicalcpu") else None)
    kv("Memory", f"{device.get('memory_gb')} GB" if device.get("memory_gb") else None)
    kv("Shell", device.get("shell"))
    kv("Terminal", device.get("terminal"))
    kv("Timezone", " / ".join(device.get("timezone") or []))
    up = device.get("uptime") or {}
    kv("Booted", up.get("booted_at"))
    kv("Uptime", up.get("uptime"))
    batt = device.get("battery")
    if batt:
        print(_c(Style.DIM, "  Battery:"))
        for line in batt.splitlines():
            print(f"    {line}")
    logged = device.get("logged_in") or []
    if logged:
        print(_c(Style.DIM, "  Logged-in sessions:"))
        for line in logged:
            print(f"    {line}")

    heading("Network interfaces")
    for iface in device.get("interfaces") or []:
        addrs = iface.get("ipv4") or []
        v6 = [a for a in (iface.get("ipv6") or []) if not a.lower().startswith("fe80")]
        ll = [a for a in (iface.get("ipv6") or []) if a.lower().startswith("fe80")]
        kind = iface.get("kind") or iface.get("media") or ""
        status = iface.get("status") or ""
        title = f"{iface['name']}"
        extras = [x for x in (kind, status) if x]
        if extras:
            title += f"  ({', '.join(extras)})"
        print(_c(Style.BOLD, f"  {title}"))
        kv("MAC", iface.get("mac"), indent=4)
        kv("IPv4", addrs, indent=4)
        kv("Netmask", iface.get("netmasks"), indent=4)
        kv("IPv6", v6, indent=4)
        kv("Link-local", ll, indent=4)
        kv("MTU", iface.get("mtu"), indent=4)

    route = device.get("default_route") or {}
    heading("Routing & DNS")
    kv("Default gateway", route.get("gateway"))
    kv("Default interface", route.get("interface"))
    dns = device.get("dns") or {}
    kv("DNS servers", dns.get("nameservers"))
    kv("Search domains", dns.get("search"))
    proxy = device.get("proxy") or {}
    if proxy:
        print(_c(Style.DIM, "  Proxy:"))
        for k, v in proxy.items():
            kv(k, v, indent=4)

    socks = device.get("sockets") or {}
    heading("Listening TCP & current connections")
    listening = socks.get("listening") or []
    if listening:
        print(_c(Style.DIM, "  Listening:"))
        for line in listening[:40]:
            print(f"    {line}")
        if len(listening) > 40:
            print(f"    … {len(listening) - 40} more")
    remotes = socks.get("established_remotes") or []
    if remotes:
        print(_c(Style.DIM, "  Established remotes:"))
        for line in remotes[:30]:
            print(f"    {line}")


def print_wifi(wifi: dict[str, Any], public: dict[str, Any]) -> None:
    heading("Wi-Fi / LAN session")
    s = summarize_wifi(wifi)
    kv("SSID", s.get("ssid"))
    kv("Interface", f"{s.get('interface')} ({s.get('kind')})" if s.get("kind") else s.get("interface"))
    kv("This device IPv4", s.get("ipv4"))
    kv("This device IPv6", [a for a in (s.get("ipv6") or []) if not a.lower().startswith("fe80")])
    kv("This device MAC", s.get("mac"))
    kv("Subnet", s.get("subnet"))
    kv("Gateway", s.get("gateway"))
    kv("Channel", s.get("channel"))
    kv("PHY mode", s.get("phymode"))
    kv("Security", s.get("security"))
    kv("Signal / noise", s.get("signal_noise"))
    kv("Country code", s.get("country"))
    kv("DHCP server", s.get("dhcp_server"))
    kv("DHCP routers", s.get("router_opt"))
    kv("DHCP domain", s.get("domain_name"))
    kv("DHCP lease", s.get("lease_time"))
    ns = s.get("networksetup") or {}
    kv("IPv4 config", ns.get("IP address") and f"{ns.get('IP address')}  router={ns.get('Router')}  mask={ns.get('Subnet mask')}")
    vpn = s.get("vpn") or {}
    if vpn:
        kv("VPN tunnel", f"{vpn.get('interface')}  gateway={vpn.get('gateway')}  (default route goes here)")
    others = s.get("other_local_ssids") or []
    if others:
        kv("Other SSIDs in range (names only)", others[:20])

    heading("Public IP (WAN)")
    if public.get("error"):
        kv("Lookup", public.get("error"))
    else:
        kv("Public IP", public.get("ip") or public.get("ip_addr"))
        kv("Hostname", public.get("hostname"))
        kv("ISP / org", public.get("org"))
        loc = ", ".join(x for x in [public.get("city"), public.get("region"), public.get("country")] if x)
        kv("Geo (ISP-level)", loc or public.get("loc"))
        kv("Timezone", public.get("timezone"))
        kv("Source", public.get("source"))


def print_hosts(hosts: list[Host], self_ips: set[str]) -> None:
    heading(f"Devices on the LAN  ({len(hosts)} found)")
    others = [h for h in hosts if not h.is_self]
    print(_c(Style.DIM, f"  Including this device: {len(hosts)}  |  others: {len(others)}"))
    for host in hosts:
        tags = []
        if host.is_self:
            tags.append("YOU")
        if host.is_gateway:
            tags.append("GATEWAY")
        tag = f"  [{', '.join(tags)}]" if tags else ""
        title = host.ip
        print()
        print(_c(Style.BOLD + Style.GREEN, f"  {title}") + _c(Style.YELLOW, tag))
        kv("Type", host.guessed_type, indent=4)
        kv("Model", host.model, indent=4)
        kv("OS guess", host.os_guess, indent=4)
        kv("MAC", host.mac, indent=4)
        kv("Vendor", host.vendor, indent=4)
        kv("Names", host.names, indent=4)
        kv("IPv6", [a for a in host.ipv6 if not a.lower().startswith("fe80:")] or None, indent=4)
        kv("Link-local v6", [a for a in host.ipv6 if a.lower().startswith("fe80:")] or None, indent=4)
        kv("Bonjour services", host.mdns_services, indent=4)
        if host.ssdp:
            bits = [f"{k}={v}" for k, v in host.ssdp.items() if k != "server"]
            if host.ssdp.get("server"):
                bits.append(f"server={host.ssdp['server']}")
            if bits:
                kv("UPnP/SSDP", "; ".join(bits), indent=4)
        if host.txt:
            interesting = {k: v for k, v in host.txt.items() if k.lower() in {
                "model", "am", "fn", "md", "ty", "rp", "f", "gateway_http",
                "serialnumber", "vendor", "vers", "protovers", "osxvers",
            } or len(host.txt) <= 8}
            if interesting:
                kv("mDNS TXT", ", ".join(f"{k}={v}" for k, v in interesting.items()), indent=4)
        kv("Open ident ports", host.open_ports, indent=4)
        if host.banners:
            kv("Banners", "; ".join(f"{k}: {v}" for k, v in host.banners.items()), indent=4)
        if host.risks:
            print(f"    {_c(Style.YELLOW + Style.BOLD, 'Exposure:')}")
            for r in host.risks:
                print(f"      {_c(Style.YELLOW, '• ' + r)}")
        kv("Seen via", host.source, indent=4)


def print_exposure(hosts: list[Host]) -> None:
    flagged = [h for h in hosts if h.risks]
    heading(f"Exposure findings  ({len(flagged)} host(s) with notes)")
    if not flagged:
        print("  No plaintext/admin services detected on the scanned ports. Good.")
        return
    print(_c(Style.DIM, "  Informational only — services reachable on the LAN, not exploited."))
    for host in flagged:
        label = host.guessed_type or "host"
        name = host.names[0] if host.names else ""
        header = f"{host.ip}  {label}" + (f"  ({name})" if name else "")
        print()
        print(_c(Style.BOLD, f"  {header}"))
        for r in host.risks:
            print(f"      {_c(Style.YELLOW, '• ' + r)}")
    print()
    print(_c(Style.DIM, "  Hardening ideas: disable Telnet/plaintext admin, put IoT on a guest"))
    print(_c(Style.DIM, "  VLAN/SSID, patch firmware, and require strong unique device passwords."))


def print_bluetooth(bt: dict[str, Any]) -> None:
    if not bt or not bt.get("available"):
        return
    devices = bt.get("devices") or []
    heading(f"Bluetooth  ({len(devices)} paired/known device(s))")
    ctrl = bt.get("controller") or {}
    if ctrl:
        state = ctrl.get("state", "")
        kv("Controller", f"{ctrl.get('chipset','?')}  fw {ctrl.get('firmware','?')}  ({state})")
        kv("Vendor / transport", " / ".join(x for x in (ctrl.get("vendor"), ctrl.get("transport")) if x))
    print(_c(Style.DIM, "  Silent: this reads devices macOS already knows; nothing is transmitted."))
    for dev in devices:
        line = _c(Style.BOLD, f"  {dev.get('name', 'Unknown')}")
        if dev.get("connected"):
            line += _c(Style.GREEN, "  [connected]")
        print()
        print(line)
        kv("Address", dev.get("address"), indent=4)
        kv("Type", dev.get("minor_type") or dev.get("major_type") or dev.get("type"), indent=4)
        kv("Vendor", dev.get("vendor"), indent=4)
        kv("RSSI", dev.get("rssi"), indent=4)
        kv("Battery", dev.get("battery"), indent=4)
        kv("Firmware", dev.get("firmware"), indent=4)
    if not devices:
        print("  Bluetooth is on but no devices are currently paired/known.")


def print_ble_scan(ble: dict[str, Any]) -> None:
    if not ble:
        return
    if not ble.get("supported"):
        heading("Nearby BLE scan")
        print(_c(Style.DIM, "  Skipped — `bleak` is not installed (pip install bleak)."))
        return
    if not ble.get("available"):
        heading("Nearby BLE scan")
        print(_c(Style.YELLOW, f"  Scan failed: {ble.get('error', 'unknown error')}"))
        print(_c(Style.DIM, "  On macOS, grant your terminal Bluetooth permission and retry."))
        return
    devices = ble.get("devices") or []
    named = ble.get("named_count", 0)
    heading(f"Nearby BLE scan  ({len(devices)} advertisers, {named} named)")
    print(_c(Style.DIM, "  Receive-only: reads advertisements devices already broadcast; nothing is paired or contacted."))
    for dev in devices:
        label = dev.get("name") or dev.get("guess") or "(unnamed)"
        rssi = dev.get("rssi")
        line = _c(Style.BOLD, f"  {label}")
        if rssi is not None:
            line += _c(Style.DIM, f"  {rssi} dBm")
        print(line)
        bits = []
        if dev.get("guess") and dev.get("guess") != dev.get("name"):
            bits.append(f"type={dev['guess']}")
        if dev.get("apple_type"):
            bits.append(f"apple={dev['apple_type']}")
        if dev.get("companies"):
            bits.append("mfr=" + ", ".join(dev["companies"][:3]))
        if dev.get("service_uuids"):
            bits.append(f"services={len(dev['service_uuids'])}")
        bits.append(f"id={dev.get('address')}")
        print(_c(Style.DIM, "      " + "  |  ".join(bits)))


def print_notes(net: str | None) -> None:
    heading("Notes")
    print("  • Sleeping phones often omit ARP until they talk; rerun while they are awake.")
    print("  • Randomized Wi-Fi MACs hide the real vendor — that is expected on modern phones.")
    print("  • SSDP/UPnP + mDNS reveal models only for devices that advertise them.")
    print("  • BSSID / some Wi-Fi fields need Location permission (or sudo wdutil) on recent macOS.")
    print("  • Service checks only connect to common identification ports; they do not exploit hosts.")
    print("  • Bluetooth list is paired/known devices only (silent); nearby unpaired scan needs `bleak`.")
    print("  • For deeper fingerprinting (JA3/JA4 TLS, p0f, full OUI), install optional libs — see README.")
    if net and ipaddress.IPv4Network(net).prefixlen < 24:
        print("  • Subnet is larger than /24; discovery was limited to this host's /24.")
    print("  • Only use this on networks you own or have permission to inventory.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_report(args: argparse.Namespace) -> dict[str, Any]:
    print(_c(Style.BOLD, "Local network inventory"))
    print(_c(Style.DIM, "Collecting device, Wi-Fi, and LAN neighbors…"))

    device, ifaces = collect_device()
    route = device.get("default_route") or {}
    wifi = collect_wifi(ifaces, route)
    if args.subnet:
        wifi["subnet"] = args.subnet

    self_ips = set()
    lan_ip = (wifi.get("active_ipv4") or [None])[0]
    if lan_ip:
        self_ips.add(lan_ip)

    public: dict[str, Any] = {}
    if not args.offline:
        print(_c(Style.DIM, "  Looking up public IP…"))
        public = public_ip_info()

    bluetooth: dict[str, Any] = {}
    if not getattr(args, "no_bluetooth", False):
        print(_c(Style.DIM, "  Reading paired/connected Bluetooth (silent, local only)…"))
        bluetooth = collect_bluetooth()

    ble: dict[str, Any] = {}
    if getattr(args, "ble_scan", False):
        secs = getattr(args, "ble_seconds", 6.0)
        print(_c(Style.DIM, f"  Scanning nearby BLE advertisers for {secs:.0f}s (receive-only)…"))
        ble = collect_ble_scan(secs)

    hosts: list[Host] = []
    subnet = wifi.get("subnet")
    if subnet:
        hosts = discover_hosts(
            subnet=subnet,
            self_ips=self_ips,
            gateway=wifi.get("gateway"),
            fast=args.fast,
            probe=not args.no_probe,
            probe_timeout=args.probe_timeout,
            mdns_seconds=args.mdns_seconds,
            online_oui=not args.offline,
            lan_ip=lan_ip,
            lan_iface=wifi.get("active_interface"),
        )
    else:
        print(_c(Style.YELLOW, "  Could not determine a local IPv4 subnet; skipping neighbor scan."))

    report = {
        "device": device,
        "wifi": wifi,
        "wifi_summary": summarize_wifi(wifi),
        "public_ip": public,
        "bluetooth": bluetooth,
        "ble_scan": ble,
        "hosts": [asdict(h) for h in hosts],
        "host_count": len(hosts),
        "other_host_count": len([h for h in hosts if not h.is_self]),
    }
    return report, hosts, self_ips, device, wifi, public, bluetooth, ble


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Inventory this device, the Wi-Fi/LAN session, and other hosts on the subnet.",
        epilog="Example: python3 network_inventory.py --json -o report.json",
    )
    p.add_argument("--json", action="store_true", help="Print JSON instead of a human report")
    p.add_argument("-o", "--output", help="Write JSON report to this file")
    p.add_argument("--fast", action="store_true", help="Skip full ping sweep and shorten mDNS/NetBIOS")
    p.add_argument("--no-probe", action="store_true", help="Do not connect to identification ports")
    p.add_argument("--offline", action="store_true", help="No public-IP or MAC-vendor HTTP lookups")
    p.add_argument("--subnet", help="Override subnet, e.g. 192.168.1.0/24")
    p.add_argument("--mdns-seconds", type=float, default=3.0, help="How long to listen for Bonjour (default 3)")
    p.add_argument("--probe-timeout", type=float, default=0.45, help="Per-port connect timeout")
    p.add_argument("--no-bluetooth", action="store_true", help="Skip the silent Bluetooth inventory")
    p.add_argument("--ble-scan", action="store_true", help="Scan for nearby BLE advertisers (needs `bleak`)")
    p.add_argument("--ble-seconds", type=float, default=6.0, help="BLE scan duration (default 6)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global IS_TTY
    args = parse_args(argv)
    if args.no_color:
        IS_TTY = False
    try:
        report, hosts, self_ips, device, wifi, public, bluetooth, ble = build_report(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(_c(Style.GREEN, f"\nWrote JSON to {args.output}"))

    if args.json and not args.output:
        json.dump(report, sys.stdout, indent=2, default=str)
        print()
        return 0
    if args.json and args.output:
        return 0

    print_device(device)
    print_wifi(wifi, public)
    print_bluetooth(bluetooth)
    print_ble_scan(ble)
    print_hosts(hosts, self_ips)
    print_exposure(hosts)
    print_notes(wifi.get("subnet"))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
