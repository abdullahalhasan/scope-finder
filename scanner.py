# scanner.py
import time
import ipaddress
import re
import socket
import subprocess
import struct
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional, Set, Any, Tuple


# -----------------------------
# Models
# -----------------------------
@dataclass
class PortInfo:
    port: int
    protocol: str
    service: str
    state: str
    banner: Optional[str] = None  # crude banner info


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    ports: List[PortInfo] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)


# -----------------------------
# Exclusions / Exceptions
# -----------------------------
_EXCLUSION_TOKEN_SPLIT = re.compile(r"[,\s;]+")


def _expand_ip_range(token: str) -> List[str]:
    """
    Expand '192.168.1.10-20' or '192.168.1.10-192.168.1.20'
    """
    token = token.strip()
    if "-" not in token:
        return []

    left, right = token.split("-", 1)
    left = left.strip()
    right = right.strip()

    start = ipaddress.ip_address(left)

    # short range: 192.168.1.10-20
    if re.fullmatch(r"\d{1,3}", right):
        octets = left.split(".")
        if len(octets) != 4:
            raise ValueError(f"Invalid IP range token: {token}")
        end = ipaddress.ip_address(".".join(octets[:3] + [right]))
    else:
        end = ipaddress.ip_address(right)

    if start.version != 4 or end.version != 4:
        raise ValueError("Only IPv4 ranges supported in this helper.")

    if int(end) < int(start):
        raise ValueError(f"Range end < start: {token}")

    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def parse_exclusions(exclusions_text: str) -> Set[str]:
    """
    Accepts: single IP, CIDR, range, or comma/space-separated mix.
    """
    exclusions_text = (exclusions_text or "").strip()
    if not exclusions_text:
        return set()

    tokens = [t for t in _EXCLUSION_TOKEN_SPLIT.split(exclusions_text) if t]
    out: Set[str] = set()

    for token in tokens:
        token = token.strip()

        # CIDR
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            for ip in net.hosts():
                out.add(str(ip))
            continue

        # range
        if "-" in token:
            for ip in _expand_ip_range(token):
                out.add(ip)
            continue

        # single
        ipaddress.ip_address(token)  # validate
        out.add(token)

    return out


def expand_targets(target: str, exclusions: Optional[Set[str]] = None) -> List[str]:
    """
    Expand a target string into a list of IPs.
    Supports:
    - Single IP: 192.168.1.10
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.10-20 or 192.168.1.10-192.168.1.50
    """
    target = (target or "").strip()
    exclusions = exclusions or set()

    ips: List[str] = []

    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        ips = [str(ip) for ip in net.hosts()]
    elif "-" in target:
        ips = _expand_ip_range(target)
    else:
        ipaddress.ip_address(target)  # validate
        ips = [target]

    return [ip for ip in ips if ip not in exclusions]


# -----------------------------
# Windows detection heuristic
# -----------------------------
def is_probably_windows(host: HostInfo) -> bool:
    win_ports = {135, 139, 445, 3389, 5985, 5986}
    for p in host.ports:
        if p.protocol == "tcp" and p.state.lower() == "open" and p.port in win_ports:
            return True
    return False


# -----------------------------
# Basic scanning
# -----------------------------
def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    """
    Check if host is up using Windows ping command.
    Returns True if ping succeeds.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False

_ARP_LINE_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F\-]{17}|[0-9a-fA-F:]{17})\s+"
    r"(?P<type>\w+)\s*$"
)

def arp_seen(ip: str) -> bool:
    """
    Windows-only ARP cache check via `arp -a`.
    Returns True if IP is present with a MAC.
    """
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
    except Exception:
        return False

    for line in out.splitlines():
        m = _ARP_LINE_RE.match(line)
        if not m:
            continue
        if m.group("ip") == ip:
            mac = (m.group("mac") or "").lower()
            if mac and mac not in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"):
                return True
    return False

def touch_arp(ip: str) -> None:
    """
    Send a tiny UDP packet to trigger ARP resolution (no reply needed).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"\x00", (ip, 1))
    except Exception:
        pass

def is_host_up(ip: str, ping_timeout_ms: int = 800, ping_retries: int = 2) -> bool:
    # 1) Ping (fast)
    for _ in range(max(1, ping_retries)):
        if ping_host(ip, timeout_ms=ping_timeout_ms):
            return True

    # 2) ARP fallback (LAN/Wi-Fi)
    touch_arp(ip)
    time.sleep(0.05)
    if arp_seen(ip):
        return True

    return False


def tcp_scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """
    Simple TCP connect scan. Returns True if port seems open.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Best-effort banner grabber. For HTTP-ish ports, send HEAD.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # HTTP probe for common web ports (helps identify http on non-standard ports)
            if port in (80, 8080, 8000, 8443, 8181, 3500, 5000):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                except Exception:
                    pass
            else:
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass

            data = s.recv(1024)
            if not data:
                return None

            text = data.decode("latin1", errors="ignore")
            # make it readable
            text = "".join(ch if (32 <= ord(ch) <= 126) else " " for ch in text)
            return " ".join(text.split()).strip() or None
    except Exception:
        return None


def detect_service_name(port: int, protocol: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


# Small overrides for real-world ports on Windows
COMMON_PORT_SERVICES = {
    902: "vmware-authd",
    912: "vmware-authd",
    3500: "http",
    6697: "irc",
    3306: "mysql",
    5985: "winrm-http",
    5986: "winrm-https",
    47001: "winrm-http",
}


def guess_service_from_banner(port: int, banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None
    b = banner.strip().lower()

    if "vmware authentication daemon" in b:
        return "vmware-authd"
    if b.startswith("http/") or "server:" in b or "content-type:" in b:
        return "http"
    if "notice auth" in b and "irc" in b:
        return "irc"
    if "mysql" in b or "is not allowed to connect to this mysql" in b:
        return "mysql"
    if b.startswith("ssh-"):
        return "ssh"
    if b.startswith("220 ") and "ftp" in b:
        return "ftp"
    if b.startswith("220 ") and ("smtp" in b or "esmtp" in b):
        return "smtp"

    return None


def finalize_service_name(port: int, service_from_port: str, banner: Optional[str]) -> str:
    svc = service_from_port or "unknown"
    if svc in ("unknown", "") and port in COMMON_PORT_SERVICES:
        svc = COMMON_PORT_SERVICES[port]

    if svc in ("unknown", ""):
        g = guess_service_from_banner(port, banner)
        if g:
            svc = g

    return svc or "unknown"


# -----------------------------
# UDP scan + DNS probe
# -----------------------------
DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 137, 161, 500, 514, 1900]


def udp_probe(ip: str, port: int, timeout: float = 0.2, payload: bytes = b"\x00") -> Tuple[str, Optional[bytes]]:
    """
    Best-effort UDP probe.
    - If we get a response: treat as "open"
    - If no response: treat as "open|filtered" (UDP reality)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            try:
                data, _ = s.recvfrom(2048)
                if data:
                    return ("open", data)
            except socket.timeout:
                return ("open|filtered", None)
            except Exception:
                return ("open|filtered", None)
    except Exception:
        return ("open|filtered", None)


def _dns_encode_name(name: str) -> bytes:
    parts = [p for p in name.strip(".").split(".") if p]
    out = b""
    for p in parts:
        out += bytes([len(p)]) + p.encode("ascii", errors="ignore")
    return out + b"\x00"


def build_dns_query(qname: str, qtype: int = 1, qclass: int = 1) -> Tuple[int, bytes]:
    """
    Minimal DNS query packet builder.
    qtype=1 A, qclass=1 IN
    """
    txid = random.randint(0, 65535)
    flags = 0x0100  # recursion desired
    qdcount = 1
    ancount = nscount = arcount = 0
    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    question = _dns_encode_name(qname) + struct.pack("!HH", qtype, qclass)
    return txid, header + question


def _dns_decode_name(pkt: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode DNS name with compression pointers.
    Returns (name, new_offset).
    """
    labels = []
    jumped = False
    original_offset = offset

    while True:
        if offset >= len(pkt):
            return ("", offset)

        length = pkt[offset]
        if length == 0:
            offset += 1
            break

        # pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(pkt):
                return ("", offset + 1)
            ptr = ((length & 0x3F) << 8) | pkt[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = ptr
            continue

        offset += 1
        label = pkt[offset: offset + length]
        labels.append(label.decode("ascii", errors="ignore"))
        offset += length

    name = ".".join(labels)
    return (name, (original_offset if jumped else offset))


def dns_probe(ip: str, timeout: float = 0.2, qname: str = "example.com") -> Optional[Dict[str, Any]]:
    """
    Send a DNS A query to UDP/53 and parse basic response.
    Returns None if no response.
    """
    txid, query = build_dns_query(qname, qtype=1, qclass=1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, 53))
            data, _ = s.recvfrom(4096)
    except Exception:
        return None

    if not data or len(data) < 12:
        return None

    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        # still could be valid, but keep it strict
        return None

    rcode = flags & 0x000F
    ra = bool(flags & 0x0080)  # recursion available

    # skip questions
    off = 12
    for _ in range(qd):
        _, off = _dns_decode_name(data, off)
        off += 4  # qtype + qclass

    answers = []
    for _ in range(an):
        _, off = _dns_decode_name(data, off)
        if off + 10 > len(data):
            break
        atype, aclass, attl, ardlen = struct.unpack("!HHIH", data[off: off + 10])
        off += 10
        rdata = data[off: off + ardlen]
        off += ardlen

        # A record
        if atype == 1 and aclass == 1 and ardlen == 4:
            answers.append(".".join(str(b) for b in rdata))

    return {
        "qname": qname,
        "rcode": rcode,
        "recursion_available": ra,
        "answer_count": len(answers),
        "answers": answers[:20],
    }


# -----------------------------
# Concurrent host scan (TCP + optional UDP/DNS)
# -----------------------------
def scan_host(
    ip: str,
    ports: List[int],
    cancel_check: Callable[[], bool],
    *,
    max_workers: int = 200,
    connect_timeout: float = 0.5,
    banner_timeout: float = 1.0,
    enable_udp: bool = False,
    udp_ports: Optional[List[int]] = None,
    udp_timeout: float = 0.2,
    enable_dns_probe: bool = True,
    
    # progress
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    host_index: int = 0,
    host_total: int = 0,
    progress_every_n_ports: int = 25,
) -> HostInfo:
    hostname: Optional[str] = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    open_ports: List[PortInfo] = []

    tcp_total = len(ports)
    tcp_done = 0
    open_found = 0

    if progress_cb:
        progress_cb({
            "phase": "host_start",
            "message": f"Scanning host {ip}",
            "current_ip": ip,
            "host_index": host_index,
            "host_total": host_total,
            "port_total": tcp_total,
            "ports_done": 0,
            "last_port": None,
            "open_found": 0,
        })

    def _probe_tcp(port: int) -> Optional[PortInfo]:
        if cancel_check():
            return None

        if not tcp_scan_port(ip, port, timeout=connect_timeout):
            return None

        banner = grab_banner(ip, port, timeout=banner_timeout)
        service = detect_service_name(port, "tcp")
        service = finalize_service_name(port, service, banner)

        return PortInfo(
            port=port,
            protocol="tcp",
            service=service,
            state="open",
            banner=banner,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_port = {ex.submit(_probe_tcp, p): p for p in ports}

        for fut in as_completed(future_to_port):
            if cancel_check():
                for f in future_to_port:
                    f.cancel()
                break

            port = future_to_port[fut]
            res = None
            try:
                res = fut.result()
            except Exception:
                res = None

            tcp_done += 1
            if res is not None:
                open_ports.append(res)
                open_found += 1

            if progress_cb and (tcp_done % progress_every_n_ports == 0 or tcp_done == tcp_total):
                progress_cb({
                    "phase": "port_scan",
                    "message": f"{ip}: ports tested {tcp_done}/{tcp_total}",
                    "current_ip": ip,
                    "host_index": host_index,
                    "host_total": host_total,
                    "port_total": tcp_total,
                    "ports_done": tcp_done,
                    "last_port": port,
                    "open_found": open_found,
                })

    # Optional UDP scan
    if enable_udp and not cancel_check():
        udp_ports = udp_ports or DEFAULT_UDP_PORTS

        if progress_cb:
            progress_cb({
                "phase": "udp_scan",
                "message": f"{ip}: UDP probing {len(udp_ports)} ports…",
                "current_ip": ip,
                "host_index": host_index,
                "host_total": host_total,
            })

        def _probe_udp(port: int) -> Optional[PortInfo]:
            if cancel_check():
                return None

            # Special DNS probe (more reliable than generic UDP)
            if port == 53 and enable_dns_probe:
                info = dns_probe(ip, timeout=udp_timeout, qname="example.com")
                state = "open" if info else "open|filtered"
                return PortInfo(port=53, protocol="udp", service="dns", state=state, banner=None)

            state, data = udp_probe(ip, port, timeout=udp_timeout, payload=b"\x00")
            banner = None
            if data:
                try:
                    txt = data[:200].decode("latin1", errors="ignore")
                    txt = "".join(ch if (32 <= ord(ch) <= 126) else " " for ch in txt)
                    banner = " ".join(txt.split()).strip() or None
                except Exception:
                    banner = None

            service = detect_service_name(port, "udp")
            if service in ("unknown", "") and port == 123:
                service = "ntp"
            if service in ("unknown", "") and port == 161:
                service = "snmp"
            if service in ("unknown", "") and port == 1900:
                service = "ssdp"

            return PortInfo(port=port, protocol="udp", service=service, state=state, banner=banner)

        udp_results: List[PortInfo] = []
        with ThreadPoolExecutor(max_workers=min(50, max_workers)) as exu:
            futs = [exu.submit(_probe_udp, p) for p in udp_ports]
            for fut in as_completed(futs):
                if cancel_check():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r is not None:
                    udp_results.append(r)

        open_ports.extend(udp_results)

        # attach DNS details once
        if enable_dns_probe:
            info = dns_probe(ip, timeout=udp_timeout, qname="example.com")
            if info:
                # store in findings
                # (we return HostInfo at end; attach below)
                pass

    # Sort ports: tcp first then udp, then port number
    def _sort_key(p: PortInfo):
        proto_rank = 0 if p.protocol == "tcp" else 1
        return (proto_rank, p.port)

    open_ports.sort(key=_sort_key)

    host = HostInfo(ip=ip, hostname=hostname, ports=open_ports)

    if enable_udp and enable_dns_probe and not cancel_check():
        info = dns_probe(ip, timeout=udp_timeout, qname="example.com")
        if info:
            host.findings["dns"] = info

    return host



# -----------------------------
# SMB / NetBIOS / AD / Services parsers (regex-based)
# -----------------------------
NETBIOS_NAME_RE = re.compile(
    r"^(?P<name>.{1,15})\s+<(?P<suffix>[0-9A-Fa-f]{2})>\s+(?P<type>UNIQUE|GROUP)\s*(?P<flags>.*)$"
)

SMB_SHARE_RE = re.compile(
    r"^(?P<share>[\w\.\$\- ]+?)\s{2,}(?P<access>READ|WRITE|READ/WRITE|NO ACCESS|DENIED|OK|UNKNOWN)\s*(?P<remark>.*)$",
    re.IGNORECASE
)

AD_DOMAIN_RE = re.compile(r"\bDomain(?:\s+Name)?\s*[:=]\s*(?P<domain>[A-Za-z0-9\.\-]+)", re.IGNORECASE)
AD_FOREST_RE = re.compile(r"\bForest(?:\s+Name)?\s*[:=]\s*(?P<forest>[A-Za-z0-9\.\-]+)", re.IGNORECASE)
AD_DC_RE = re.compile(r"\bDomain\s*Controller\s*[:=]\s*(?P<dc>[A-Za-z0-9\.\-]+)", re.IGNORECASE)

SERVICE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_\-\. ]+?)\s{2,}(?P<state>RUNNING|STOPPED|PAUSED|START_PENDING|STOP_PENDING)\s{2,}(?P<start>AUTO|DEMAND|DISABLED|MANUAL|UNKNOWN)\b",
    re.IGNORECASE
)


def parse_netbios(raw: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = NETBIOS_NAME_RE.match(line)
        if not m:
            continue
        results.append(
            {
                "name": m.group("name").strip(),
                "suffix": m.group("suffix").upper(),
                "type": m.group("type").upper(),
                "flags": (m.group("flags") or "").strip(),
            }
        )
    return results


def parse_smb_shares(raw: str) -> List[Dict[str, str]]:
    shares: List[Dict[str, str]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith(("share", "----", "comment", "remark")):
            continue

        m = SMB_SHARE_RE.match(line)
        if not m:
            continue

        shares.append(
            {
                "share": m.group("share").strip(),
                "access": m.group("access").upper(),
                "remark": (m.group("remark") or "").strip(),
            }
        )
    return shares


def parse_ad_info(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out

    m = AD_DOMAIN_RE.search(raw)
    if m:
        out["domain"] = m.group("domain")

    m = AD_FOREST_RE.search(raw)
    if m:
        out["forest"] = m.group("forest")

    m = AD_DC_RE.search(raw)
    if m:
        out["domain_controller"] = m.group("dc")

    return out


def parse_windows_services(raw: str) -> List[Dict[str, str]]:
    services: List[Dict[str, str]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = SERVICE_RE.match(line)
        if not m:
            continue
        services.append(
            {
                "name": m.group("name").strip(),
                "state": m.group("state").upper(),
                "start": m.group("start").upper(),
            }
        )
    return services


# -----------------------------
# SAFE Collector Interface
# -----------------------------
class WindowsSMBCollector:
    def collect(self, host_ip: str) -> Dict[str, str]:
        raise NotImplementedError


class FileBlobCollector(WindowsSMBCollector):
    def __init__(self, base_dir: str = "evidence"):
        self.base_dir = base_dir

    def _read(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""

    def collect(self, host_ip: str) -> Dict[str, str]:
        import os
        host_dir = os.path.join(self.base_dir, host_ip)
        return {
            "netbios": self._read(os.path.join(host_dir, "netbios.txt")),
            "shares": self._read(os.path.join(host_dir, "shares.txt")),
            "ad": self._read(os.path.join(host_dir, "ad.txt")),
            "services": self._read(os.path.join(host_dir, "services.txt")),
        }


def enrich_host_with_windows_findings(host: HostInfo, collector: WindowsSMBCollector) -> None:
    if not is_probably_windows(host):
        return

    blobs = collector.collect(host.ip) or {}

    # helpful note when nothing exists
    if not any([
        (blobs.get("netbios") or "").strip(),
        (blobs.get("shares") or "").strip(),
        (blobs.get("ad") or "").strip(),
        (blobs.get("services") or "").strip(),
    ]):
        host.findings["windows_smb"] = {
            "note": "No evidence files found. Expected evidence/<ip>/{netbios.txt, shares.txt, ad.txt, services.txt}"
        }
        return

    host.findings["windows_smb"] = {
        "netbios_names": parse_netbios(blobs.get("netbios", "")),
        "shares": parse_smb_shares(blobs.get("shares", "")),
        "ad": parse_ad_info(blobs.get("ad", "")),
        "services": parse_windows_services(blobs.get("services", "")),
    }


# -----------------------------
# Main scan_range
# -----------------------------
def scan_range(
    target: str,
    cancel_check: Callable[[], bool],
    min_port: int = 1,
    max_port: int = 1024,
    exclusions_text: str = "",
    smb_collector: Optional[WindowsSMBCollector] = None,
    *,
    enable_udp: bool = False,
    udp_ports: Optional[List[int]] = None,
    udp_timeout: float = 0.2,
    enable_dns_probe: bool = True,
    # progress
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    progress_every_n_ports: int = 25,
) -> Dict[str, HostInfo]:
    exclude_set = parse_exclusions(exclusions_text)

    # expanded list (for excluded count and progress)
    all_ips = expand_targets(target, exclusions=set())
    excluded_list = sorted(set(all_ips) & exclude_set)
    ips = [ip for ip in all_ips if ip not in exclude_set]

    ports = list(range(min_port, max_port + 1))
    results: Dict[str, HostInfo] = {}

    host_total = len(ips)

    if progress_cb:
        progress_cb({
            "phase": "expanded",
            "message": f"Targets expanded: {host_total} hosts (excluded {len(excluded_list)})",
            "host_total": host_total,
            "excluded_count": len(excluded_list),
            "excluded_sample": excluded_list[:25],
            "port_total": len(ports),
        })

    for idx, ip in enumerate(ips, start=1):
        if cancel_check():
            break

        if progress_cb:
            progress_cb({
                "phase": "ping",
                "message": f"Pinging {ip} ({idx}/{host_total})",
                "current_ip": ip,
                "host_index": idx,
                "host_total": host_total,
                "port_total": len(ports),
                "ports_done": 0,
                "last_port": None,
            })

        if not is_host_up(ip):
            if progress_cb:
                progress_cb({
                    "phase": "host_down",
                    "message": f"{ip} did not respond to ping, skipping.",
                    "current_ip": ip,
                    "host_index": idx,
                    "host_total": host_total,
                })
            continue

        host_info = scan_host(
            ip,
            ports,
            cancel_check,
            max_workers=256,
            connect_timeout=0.5,
            banner_timeout=1.0,
            enable_udp=enable_udp,
            udp_ports=udp_ports,
            udp_timeout=udp_timeout,
            enable_dns_probe=enable_dns_probe,
            progress_cb=progress_cb,
            host_index=idx,
            host_total=host_total,
            progress_every_n_ports=progress_every_n_ports,
        )

        if smb_collector is not None:
            enrich_host_with_windows_findings(host_info, smb_collector)

        results[ip] = host_info

    if progress_cb:
        progress_cb({
            "phase": "done",
            "message": "Scan completed.",
            "current_ip": None,
        })

    return results