"""
WiFiGuard — Public WiFi Security Analyzer
Backend: Flask + ReportLab
"""

import os, io, json, time, socket, ssl, urllib.request, urllib.error, datetime, subprocess, re, threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import (Flask, request, jsonify, render_template,
                   send_file, abort)

app = Flask(__name__)
app.config['SECRET_KEY']                     = os.environ.get('SECRET_KEY', 'wifiguard-dev-secret')

# ── Local Scan Log (no auth / no DB) ─────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
SCAN_LOG_PATH = os.path.join(DATA_DIR, 'scan_history.json')
OUI_DB_PATH = os.path.join(DATA_DIR, 'oui.json')
_VENDOR_CACHE: dict[str, str] = {}
_DEVICE_SCAN_CACHE: dict[str, dict] = {}
HISTORY_TTL_HOURS = 24
HISTORY_CLEANUP_INTERVAL_SECONDS = 15 * 60  # every 15 minutes
_CLEANUP_THREAD_STARTED = False


def _ensure_data_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass


def _load_scan_log():
    _ensure_data_dir()
    try:
        with open(SCAN_LOG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _record_created_at_utc(record: dict):
    # Preferred source: created_at (ISO UTC). Legacy fallback: timestamp.
    created = record.get('created_at')
    if isinstance(created, str) and created:
        try:
            return datetime.datetime.fromisoformat(created)
        except Exception:
            pass
    ts = record.get('timestamp')
    if isinstance(ts, str) and ts:
        try:
            return datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return None


def delete_old_scans(ttl_hours: int = HISTORY_TTL_HOURS):
    """
    Remove scan records older than ttl_hours.
    Safe for background execution; never raises to caller.
    """
    try:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=ttl_hours)
        log = _load_scan_log()
        kept = []
        removed = 0
        for rec in log:
            if not isinstance(rec, dict):
                continue
            created_at = _record_created_at_utc(rec)
            if created_at is None:
                # Keep unknown legacy records rather than accidental loss.
                kept.append(rec)
                continue
            if created_at >= cutoff:
                kept.append(rec)
            else:
                removed += 1
        if removed > 0:
            _ensure_data_dir()
            with open(SCAN_LOG_PATH, 'w', encoding='utf-8') as f:
                json.dump(kept, f, ensure_ascii=False, indent=2)
            app.logger.info(f'[history_cleanup] removed={removed} ttl_hours={ttl_hours}')
    except Exception as e:
        # Do not crash app if cleanup fails.
        app.logger.warning(f'[history_cleanup] failed: {e}')


def _history_cleanup_worker():
    while True:
        delete_old_scans()
        time.sleep(HISTORY_CLEANUP_INTERVAL_SECONDS)


def start_history_cleanup_thread():
    global _CLEANUP_THREAD_STARTED
    if _CLEANUP_THREAD_STARTED:
        return
    _CLEANUP_THREAD_STARTED = True
    t = threading.Thread(target=_history_cleanup_worker, daemon=True, name='history-cleanup')
    t.start()


def _append_scan_log(entry: dict, limit: int = 50):
    # Opportunistic cleanup on write path.
    delete_old_scans()
    log = _load_scan_log()
    log.insert(0, entry)
    log = log[:limit]
    _ensure_data_dir()
    try:
        with open(SCAN_LOG_PATH, 'w', encoding='utf-8') as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _read_json_file(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json_file(path: str, data):
    _ensure_data_dir()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _normalize_mac(mac: str) -> str:
    raw = re.sub(r'[^0-9A-Fa-f]', '', (mac or ''))
    if len(raw) != 12:
        return ''
    raw = raw.upper()
    return ':'.join(raw[i:i+2] for i in range(0, 12, 2))


def _oui_prefix(mac: str) -> str:
    m = _normalize_mac(mac)
    if not m:
        return ''
    return ':'.join(m.split(':')[:3])


def _load_local_oui_db() -> dict:
    data = _read_json_file(OUI_DB_PATH)
    if isinstance(data, dict):
        return {k.upper().replace('-', ':'): str(v) for k, v in data.items()}
    return {}

# ── Network Info ─────────────────────────────────────────────────────────────

def fetch_network_info(client_ip):
    info = {'public_ip': client_ip, 'city': 'Unknown', 'region': 'Unknown',
            'country': 'Unknown', 'isp': 'Unknown', 'timezone': 'Unknown', 'loc': ''}
    try:
        target = client_ip if client_ip and client_ip not in ('127.0.0.1', '::1') else ''
        url    = f'https://ipinfo.io/{target}/json' if target else 'https://ipinfo.io/json'
        req    = urllib.request.Request(url, headers={'User-Agent': 'WiFiGuard/2.0'})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        info.update({'public_ip': data.get('ip', client_ip),
                     'city':      data.get('city',     'Unknown'),
                     'region':    data.get('region',   'Unknown'),
                     'country':   data.get('country',  'Unknown'),
                     'isp':       data.get('org',      'Unknown'),
                     'timezone':  data.get('timezone', 'Unknown'),
                     'loc':       data.get('loc',      '')})
    except Exception:
        pass
    return info

# ── Security Checks ───────────────────────────────────────────────────────────

def get_client_ip(req):
    for h in ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP']:
        v = req.headers.get(h)
        if v:
            return v.split(',')[0].strip()
    return req.remote_addr or '127.0.0.1'


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _is_private_lan_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split('.')]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return False
        if ip == '0.0.0.0':
            return False
        if ip == '127.0.0.1':
            return False
        # Filter multicast and other non-LAN ranges requested by user.
        if parts[0] in (224, 239):
            return False
        # Exclude common virtual/shared adapter ranges requested by user.
        if parts[0] == 192 and parts[1] == 168 and parts[2] in (56, 137):
            return False
        # Private ranges only
        if parts[0] == 10:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        return False
    except Exception:
        return False


def _mac_to_vendor(mac: str) -> str:
    """
    Hybrid vendor detection:
    1) API (macvendors)
    2) local OUI db + built-in map
    3) Unidentified Device
    """
    norm = _normalize_mac(mac)
    oui = _oui_prefix(norm)
    if not norm or not oui:
        return 'Unidentified Device'

    if norm in _VENDOR_CACHE:
        return _VENDOR_CACHE[norm]

    # Step 1: API lookup (short timeout; non-blocking fallback on failure)
    api_vendor = None
    api_raw = ''
    try:
        r = requests.get(f'https://api.macvendors.com/{norm}', timeout=1.5)
        api_raw = (r.text or '').strip()
        if r.status_code == 200 and api_raw and 'not found' not in api_raw.lower():
            api_vendor = api_raw
    except Exception:
        pass

    # Step 2: local OUI db fallback
    local_db = _load_local_oui_db()
    builtin_map = {
        'F4:F5:DB': 'Apple',
        'D8:50:E6': 'Apple',
        '3C:5A:37': 'Apple',
        'A4:C3:F0': 'Samsung',
        'F8:E0:79': 'Samsung',
        '7C:1D:D9': 'Xiaomi',
        'F0:B4:29': 'Xiaomi',
        '3C:97:0E': 'Intel',
        '9C:FB:98': 'Intel',
        'B4:B5:2F': 'Dell',
        '5C:51:4F': 'HP',
        'F4:F2:6D': 'TP-Link',
        '50:C7:BF': 'TP-Link',
        'C4:6E:1F': 'TP-Link',
        'B0:48:7A': 'D-Link',
    }
    vendor = api_vendor or local_db.get(oui) or builtin_map.get(oui) or 'Unidentified Device'

    # Step 3: fallback already handled via default.
    app.logger.info(f'[vendor_lookup] mac={norm} oui={oui} api_response={api_raw[:120]!r} vendor={vendor!r}')
    _VENDOR_CACHE[norm] = vendor
    return vendor


def _reverse_dns_hostname(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.strip() if host else 'No Hostname'
    except Exception:
        return 'No Hostname'


def _resolve_hostnames_parallel(ips: list[str], max_workers: int = 24) -> dict:
    out = {}
    uniq_ips = list(dict.fromkeys(ips))
    if not uniq_ips:
        return out
    workers = max(1, min(max_workers, len(uniq_ips)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_reverse_dns_hostname, ip): ip for ip in uniq_ips}
        for f, ip in futs.items():
            try:
                out[ip] = f.result(timeout=2.0)
            except Exception:
                out[ip] = 'No Hostname'
    return out


def _guess_device_type(vendor: str, hostname: str, ip: str, gateway_ip: str | None = None) -> str:
    host_l = (hostname or '').lower()
    if gateway_ip and ip == gateway_ip:
        return 'Router'
    if vendor == 'Apple' and any(k in host_l for k in ('iphone', 'ipad')):
        return 'Mobile'
    if vendor in ('Samsung', 'Xiaomi'):
        return 'Mobile'
    if vendor in ('Intel', 'Dell', 'HP') or 'desktop' in host_l or 'pc' in host_l:
        return 'Laptop/Desktop'
    if 'laptop' in host_l:
        return 'Laptop/Desktop'
    if vendor in ('TP-Link', 'D-Link') or 'router' in host_l or 'gateway' in host_l:
        return 'Router'
    if 'android' in host_l or 'iphone' in host_l:
        return 'Mobile'
    if hostname and hostname != 'No Hostname':
        return 'Generic Device'
    return 'Generic Device'


def _populate_arp_with_ping_sweep(local_ip: str):
    """
    Active discovery to populate ARP cache before reading it.
    Windows ping sweep across /24 subnet.
    """
    if not _is_private_lan_ip(local_ip):
        return
    base = '.'.join(local_ip.split('.')[:3])
    # Keep it lightweight and bounded.
    for host in range(1, 255):
        target = f'{base}.{host}'
        try:
            subprocess.run(
                ['ping', '-n', '1', '-w', '140', target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            continue


def _subnet_prefix(local_ip: str) -> str:
    try:
        a, b, c, _ = local_ip.split('.')
        return f'{int(a)}.{int(b)}.{int(c)}.'
    except Exception:
        return ''


def _ping_once(ip: str, timeout_ms: int = 300) -> bool:
    try:
        r = subprocess.run(
            ['ping', '-n', '1', '-w', str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
        return r.returncode == 0
    except Exception:
        return False


def _ping_sweep_parallel(prefix: str, max_workers: int = 80, timeout_ms: int = 300):
    if not prefix:
        return set()
    ips = [f'{prefix}{i}' for i in range(1, 255)]
    alive = set()
    workers = max(1, min(max_workers, 100))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_ping_once, ip, timeout_ms): ip for ip in ips}
        for f in as_completed(futs):
            ip = futs[f]
            try:
                if f.result():
                    alive.add(ip)
            except Exception:
                pass
    return alive


def get_default_gateway_info():
    """
    Best-effort default gateway + MAC detection (Windows-focused, fallback cross-platform).
    """
    gateway_ip = None
    gateway_mac = None
    try:
        out = subprocess.check_output(['ipconfig'], text=True, encoding='utf-8', errors='ignore')
        m = re.findall(r'Default Gateway[ .:]*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', out)
        if m:
            gateway_ip = m[-1]
    except Exception:
        pass

    # Fallback route print parse
    if not gateway_ip:
        try:
            out = subprocess.check_output(['route', 'print', '0.0.0.0'], text=True, encoding='utf-8', errors='ignore')
            for line in out.splitlines():
                if line.strip().startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway_ip = parts[2]
                        break
        except Exception:
            pass

    # ARP lookup for gateway MAC
    if gateway_ip:
        try:
            arp = subprocess.check_output(['arp', '-a'], text=True, encoding='utf-8', errors='ignore')
            for line in arp.splitlines():
                if gateway_ip in line:
                    macs = re.findall(r'([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})', line)
                    if macs:
                        gateway_mac = macs[0].lower().replace('-', ':')
                        break
        except Exception:
            pass

    return {'ip': gateway_ip or 'Unknown', 'mac': gateway_mac or 'Unknown'}


def scan_local_devices_from_arp(local_ip: str, gateway_ip: str | None = None, mode: str = 'quick'):
    prefix = _subnet_prefix(local_ip)
    if not prefix:
        return []

    cache_key = f'{mode}:{prefix}'
    now = time.time()
    cached = _DEVICE_SCAN_CACHE.get(cache_key)
    if cached and (now - cached.get('ts', 0) <= 30):
        return cached.get('devices', [])

    # Quick: ARP only. Full: ping sweep + ARP (faster parallel probing).
    alive = set()
    if mode == 'full':
        alive = _ping_sweep_parallel(prefix, max_workers=80, timeout_ms=300)

    devices = []
    try:
        out = subprocess.check_output(['arp', '-a'], text=True, encoding='utf-8', errors='ignore')
        for line in out.splitlines():
            ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})', line)
            if not ip_match or not mac_match:
                continue
            ip = ip_match.group(1)
            mac = _normalize_mac(mac_match.group(1))
            # Strict filtering for realistic results.
            if not _is_private_lan_ip(ip):
                continue
            if not ip.startswith(prefix):
                continue
            if not mac:
                continue
            if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                continue
            if 'incomplete' in line.lower():
                continue
            devices.append({
                'ip': ip,
                'mac': mac,
                'vendor': 'Unidentified Device',
                'hostname': 'No Hostname',
                'type': 'Unknown',
            })
    except Exception:
        pass

    # If ARP was empty in full mode, run a fallback sweep on the common home subnet.
    if mode == 'full' and not devices and prefix != '192.168.1.':
        try:
            _ping_sweep_parallel('192.168.1.', max_workers=80, timeout_ms=300)
            out = subprocess.check_output(['arp', '-a'], text=True, encoding='utf-8', errors='ignore')
            for line in out.splitlines():
                ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', line)
                mac_match = re.search(r'([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})', line)
                if not ip_match or not mac_match:
                    continue
                ip = ip_match.group(1)
                mac = _normalize_mac(mac_match.group(1))
                if not _is_private_lan_ip(ip):
                    continue
                if not ip.startswith('192.168.1.'):
                    continue
                if not mac or mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                    continue
                if 'incomplete' in line.lower():
                    continue
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': 'Unidentified Device',
                    'hostname': 'No Hostname',
                    'type': 'Unknown',
                })
        except Exception:
            pass

    # De-duplicate by ip+mac
    uniq = []
    seen = set()
    for d in devices:
        key = (d['ip'], d['mac'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)

    # In full mode, keep only active responders (plus gateway).
    if mode == 'full' and alive:
        uniq = [d for d in uniq if d['ip'] in alive or (gateway_ip and d['ip'] == gateway_ip)]

    # Parallel hostname + vendor enrichment for speed.
    def enrich_device(dev: dict):
        ip = dev['ip']
        mac = dev['mac']
        hostname = _reverse_dns_hostname(ip)
        vendor = _mac_to_vendor(mac)
        dtype = _guess_device_type(vendor, hostname, ip, gateway_ip=gateway_ip)
        out_d = dict(dev)
        out_d['hostname'] = hostname if hostname else 'No Hostname'
        out_d['vendor'] = vendor
        out_d['type'] = dtype
        return out_d

    enriched = []
    workers = max(1, min(50, len(uniq) or 1))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(enrich_device, d) for d in uniq]
        for f in as_completed(futs):
            try:
                enriched.append(f.result())
            except Exception:
                pass
    uniq = enriched

    uniq.sort(key=lambda x: tuple(int(p) for p in x['ip'].split('.')))
    uniq = uniq[:64]
    _DEVICE_SCAN_CACHE[cache_key] = {'ts': now, 'devices': uniq}
    return uniq


def check_https_connectivity(urls=None):
    urls = urls or ['https://www.google.com', 'https://www.cloudflare.com', 'https://www.github.com']
    results = []
    for url in urls:
        try:
            start = time.time()
            req   = urllib.request.Request(url, headers={'User-Agent': 'WiFiGuard/2.0'})
            with urllib.request.urlopen(req, timeout=5) as r:
                results.append({'url': url, 'status': r.status, 'ok': r.status == 200,
                                'latency_ms': round((time.time()-start)*1000)})
        except Exception as e:
            results.append({'url': url, 'ok': False, 'error': str(e)[:80]})
    return results


def check_ssl_certificates(domains=None):
    domains = domains or [('www.google.com', 443), ('www.cloudflare.com', 443)]
    results = []
    for host, port in domains:
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=5),
                                   server_hostname=host)
            cert = conn.getpeercert(); conn.close()
            sans = [v for (k, v) in cert.get('subjectAltName', []) if k == 'DNS']
            hostname_match = any(
                s == host or (s.startswith('*.') and host.endswith(s[1:]))
                for s in (sans or [host])
            )
            exp  = cert.get('notAfter', '')
            secs = ssl.cert_time_to_seconds(exp) if exp else None
            days = round((secs - time.time()) / 86400) if secs else None
            results.append({'host': host, 'valid': True, 'hostname_match': hostname_match,
                            'expires': exp, 'days_until_expiry': days})
        except ssl.SSLCertVerificationError as e:
            results.append({'host': host, 'valid': False,
                            'error': 'Certificate verification failed', 'detail': str(e)[:100]})
        except Exception as e:
            results.append({'host': host, 'valid': False, 'error': str(e)[:100]})
    return results


def check_dns_behavior(domains=None):
    domains = domains or {'google.com':    ['142.250.','172.217.','216.58.','74.125.'],
                          'cloudflare.com':['104.16.', '104.17.', '104.18.','104.19.']}
    results = []; suspicious = False
    for domain, prefixes in domains.items():
        try:
            addrs   = list({r[4][0] for r in socket.getaddrinfo(domain, None)})
            matched = any(any(a.startswith(p) for p in prefixes) for a in addrs)
            if not matched: suspicious = True
            results.append({'domain': domain, 'resolved_ips': addrs, 'expected_prefix_match': matched})
        except Exception as e:
            results.append({'domain': domain, 'error': str(e)[:80]})
    return results, suspicious


def _dns_query_a_udp(server_ip: str, domain: str, timeout: float = 2.0):
    """
    Minimal UDP DNS A query (no external deps). Returns list of IPv4 strings.
    """
    tid = os.urandom(2)
    # Flags: recursion desired
    flags = b'\x01\x00'
    header = tid + flags + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'

    qname = b''.join(
        len(p).to_bytes(1, 'big') + p.encode('ascii', 'ignore')
        for p in domain.split('.')
    ) + b'\x00'
    packet = header + qname + b'\x00\x01' + b'\x00\x01'  # QTYPE=A, QCLASS=IN

    def read_name(msg: bytes, off: int):
        """
        Read a possibly-compressed DNS name.
        Returns (name, new_offset).
        """
        labels = []
        jumped = False
        original_off = off
        # Prevent infinite loops
        for _ in range(50):
            if off >= len(msg):
                break
            length = msg[off]
            # Pointer: 11xxxxxx xxxxxxxx
            if (length & 0xC0) == 0xC0:
                if off + 1 >= len(msg):
                    break
                ptr = ((length & 0x3F) << 8) | msg[off + 1]
                off = ptr
                jumped = True
                off_after_pointer = original_off + 2
                original_off = off_after_pointer
                continue
            if length == 0:
                # End of name
                off += 1
                return '.'.join(labels), (original_off if jumped else off)
            off += 1
            if off + length > len(msg):
                break
            labels.append(msg[off:off + length].decode('ascii', 'ignore'))
            off += length
        # Fallback
        return '.'.join(labels), off

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (server_ip, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()

    if len(data) < 12 or data[:2] != tid:
        return []

    qd = int.from_bytes(data[4:6], 'big')
    an = int.from_bytes(data[6:8], 'big')
    ns = int.from_bytes(data[8:10], 'big')
    ar = int.from_bytes(data[10:12], 'big')

    off = 12
    # Skip questions
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4  # QTYPE + QCLASS

    rrs_total = an + ns + ar
    ips = []
    for _ in range(rrs_total):
        if off >= len(data):
            break
        _, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype = int.from_bytes(data[off:off + 2], 'big'); off += 2
        _rclass = int.from_bytes(data[off:off + 2], 'big'); off += 2
        off += 4  # ttl
        rdlen = int.from_bytes(data[off:off + 2], 'big'); off += 2
        if rdlen < 0 or off + rdlen > len(data):
            break
        rdata = data[off:off + rdlen]; off += rdlen
        # A record
        if rtype == 1 and rdlen == 4:
            ips.append('.'.join(str(b) for b in rdata))

    uniq = list(dict.fromkeys(ips))
    if uniq:
        return uniq

    # UDP fallback: some networks block UDP/53.
    try:
        uniq_tcp = _dns_query_a_tcp(server_ip, domain, timeout=timeout)
        if uniq_tcp:
            return uniq_tcp
    except Exception:
        pass

    # Final fallback: DNS-over-HTTPS (DoH) without using DNS for the resolver hostname.
    try:
        return _dns_query_a_doh_cloudflare(domain, timeout=timeout)
    except Exception:
        return uniq


def _dns_query_a_tcp(server_ip: str, domain: str, timeout: float = 2.0):
    """
    DNS A query over TCP to a DNS server. Returns list of IPv4 strings.
    """
    tid = os.urandom(2)
    flags = b'\x01\x00'  # recursion desired
    header = tid + flags + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'

    qname = b''.join(
        len(p).to_bytes(1, 'big') + p.encode('ascii', 'ignore')
        for p in domain.split('.')
    ) + b'\x00'
    packet = header + qname + b'\x00\x01' + b'\x00\x01'

    def read_name(msg: bytes, off: int):
        labels = []
        jumped = False
        original_off = off
        for _ in range(50):
            if off >= len(msg):
                break
            length = msg[off]
            if (length & 0xC0) == 0xC0:
                if off + 1 >= len(msg):
                    break
                ptr = ((length & 0x3F) << 8) | msg[off + 1]
                off = ptr
                jumped = True
                off_after_pointer = original_off + 2
                original_off = off_after_pointer
                continue
            if length == 0:
                off += 1
                return '.'.join(labels), (original_off if jumped else off)
            off += 1
            if off + length > len(msg):
                break
            labels.append(msg[off:off + length].decode('ascii', 'ignore'))
            off += length
        return '.'.join(labels), off

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server_ip, 53))
        msg_len = len(packet).to_bytes(2, 'big')
        s.sendall(msg_len + packet)

        # Read length prefix
        lb = b''
        while len(lb) < 2:
            chunk = s.recv(2 - len(lb))
            if not chunk:
                break
            lb += chunk
        if len(lb) != 2:
            return []
        resp_len = int.from_bytes(lb, 'big')
        data = b''
        while len(data) < resp_len:
            chunk = s.recv(min(4096, resp_len - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        s.close()

    if len(data) < 12 or data[:2] != tid:
        # Tid mismatch can happen across retries; don't hard-fail parsing.
        pass

    if len(data) < 12:
        return []

    qd = int.from_bytes(data[4:6], 'big')
    an = int.from_bytes(data[6:8], 'big')
    ns = int.from_bytes(data[8:10], 'big')
    ar = int.from_bytes(data[10:12], 'big')

    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4

    rrs_total = an + ns + ar
    ips = []
    for _ in range(rrs_total):
        if off >= len(data):
            break
        _, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype = int.from_bytes(data[off:off + 2], 'big'); off += 2
        _rclass = int.from_bytes(data[off:off + 2], 'big'); off += 2
        off += 4
        rdlen = int.from_bytes(data[off:off + 2], 'big'); off += 2
        if rdlen < 0 or off + rdlen > len(data):
            break
        rdata = data[off:off + rdlen]; off += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append('.'.join(str(b) for b in rdata))

    return list(dict.fromkeys(ips))


def _dns_query_a_doh_cloudflare(domain: str, timeout: float = 3.0):
    """
    DNS-over-HTTPS fallback that queries Cloudflare DoH at 1.1.1.1 (by IP).
    Returns list of IPv4 strings.
    """
    # Connect to Cloudflare by IP to avoid DNS resolution.
    doh_ip = '1.1.1.1'
    doh_host = 'cloudflare-dns.com'

    # Build request path. Domain is already DNS-label safe (letters, digits, dots).
    path = f'/dns-query?name={domain}&type=A&ct=application/dns-json'

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((doh_ip, 443), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=doh_host)
    try:
        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {doh_host}\r\n'
            f'Accept: application/dns-json\r\n'
            f'Connection: close\r\n\r\n'
        ).encode('ascii', 'ignore')
        ssock.sendall(req)

        chunks = []
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            chunks.append(data)
        raw = b''.join(chunks)
    finally:
        try:
            ssock.close()
        except Exception:
            pass

    if b'\r\n\r\n' not in raw:
        return []
    header_blob, body = raw.split(b'\r\n\r\n', 1)
    header_line = header_blob.split(b'\r\n', 1)[0]
    parts = header_line.split(b' ')
    if len(parts) < 2:
        return []
    status_code = int(parts[1])
    if status_code != 200:
        return []

    j = json.loads(body.decode('utf-8', 'ignore'))
    ans = j.get('Answer', []) or []
    ips = []
    for a in ans:
        if a.get('type') == 1 and a.get('data'):
            ips.append(a.get('data'))
    return list(dict.fromkeys([ip for ip in ips if isinstance(ip, str) and ip.strip()]))


def check_dns_reputation_with_trusted():
    """
    Compare system resolver results with trusted DNS (8.8.8.8).
    """
    domains = ['google.com', 'cloudflare.com', 'github.com']
    results = []
    mismatch = False
    for d in domains:
        try:
            system_ips = list({r[4][0] for r in socket.getaddrinfo(d, None)})
            system_err = None
        except Exception as e:
            system_ips = []
            system_err = str(e)[:80]

        try:
            trusted_ips = _dns_query_a_udp('8.8.8.8', d, timeout=2.0)
            trusted_err = None
        except Exception as e:
            trusted_ips = []
            trusted_err = str(e)[:80]

        overlap = bool(set(system_ips) & set(trusted_ips)) if system_ips and trusted_ips else None
        is_mismatch = (overlap is False)
        if is_mismatch:
            mismatch = True
        results.append({
            'domain': d,
            'system_ips': system_ips,
            'trusted_dns': '8.8.8.8',
            'trusted_ips': trusted_ips,
            'overlap': overlap,
            'mismatch': is_mismatch,
            'system_error': system_err,
            'trusted_error': trusted_err,
        })
    return results, mismatch


def check_captive_portal():
    tests = [('http://connectivitycheck.gstatic.com/generate_204', 204),
             ('http://www.msftconnecttest.com/connecttest.txt',    200)]
    detected = False; details = []
    for url, expected in tests:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'WiFiGuard/2.0'})
            with urllib.request.urlopen(req, timeout=5) as r:
                intercepted = r.status != expected or r.url != url
                if intercepted: detected = True
                details.append({'url': url, 'expected_code': expected, 'actual_code': r.status,
                                'final_url': r.url, 'intercepted': intercepted})
        except urllib.error.HTTPError as e:
            detected = True
            details.append({'url': url, 'error': f'HTTP {e.code}', 'intercepted': True})
        except Exception as e:
            details.append({'url': url, 'error': str(e)[:80], 'intercepted': False})
    return details, detected


def check_suspicious_redirects(sites=None):
    sites = sites or ['http://www.google.com', 'http://www.github.com']
    results = []; suspicious = False
    for url in sites:
        try:
            req    = urllib.request.Request(url, headers={'User-Agent': 'WiFiGuard/2.0'})
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            with opener.open(req, timeout=5) as r:
                is_https = r.url.startswith('https://')
                if not is_https: suspicious = True
                results.append({'original': url, 'final': r.url, 'upgraded_to_https': is_https})
        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location', '')
            upgraded = loc.startswith('https://')
            if not upgraded: suspicious = True
            results.append({'original': url, 'redirect_location': loc, 'upgraded_to_https': upgraded})
        except Exception as e:
            results.append({'original': url, 'error': str(e)[:80]})
    return results, suspicious


def check_mitm_heuristics(ssl_results, dns_results, https_results):
    w = []
    failed_ssl = [r for r in ssl_results if not r.get('valid')]
    if failed_ssl:
        w.append(f'SSL validation failed for {len(failed_ssl)} domain(s) — possible certificate interception')
    host_mismatch = [r for r in ssl_results if r.get('valid') and r.get('hostname_match') is False]
    if host_mismatch:
        w.append(f'SSL hostname mismatch for {len(host_mismatch)} domain(s) — possible TLS interception')
    for r in dns_results:
        if not r.get('expected_prefix_match') and 'error' not in r:
            w.append(f'DNS for {r["domain"]} returned unexpected IPs {r.get("resolved_ips")} — possible DNS poisoning')
    slow = [r for r in https_results if r.get('ok') and r.get('latency_ms', 0) > 2000]
    if slow:
        w.append(f'High HTTPS latency on {len(slow)} endpoint(s) — possible traffic inspection proxy')
    if sum(1 for r in https_results if not r.get('ok')) >= 2:
        w.append('Multiple HTTPS connections failed — network may be blocking secure traffic')
    return w

# ── Scoring (start 100, deduct) ───────────────────────────────────────────────

def calculate_risk_score(https_results, ssl_results, dns_suspicious,
                          captive_portal, redirect_suspicious, mitm_warnings,
                          dns_trusted_mismatch=False):
    """
    Calibrated scoring model focused on real indicators.
    Starts at 0 and adds trust points for passed controls.
    """
    score = 0
    breakdown = {}

    failed_https = sum(1 for r in https_results if not r.get('ok'))
    https_points = 20 if failed_https == 0 else max(0, 20 - failed_https * 7)
    score += https_points
    breakdown['https_connectivity'] = {
        'points': https_points,
        'max': 20,
        'detail': 'HTTPS connectivity across known domains'
    }

    failed_ssl = sum(1 for r in ssl_results if not r.get('valid'))
    ssl_points = 20 if failed_ssl == 0 else max(0, 20 - failed_ssl * 12)
    score += ssl_points
    breakdown['ssl_validation'] = {
        'points': ssl_points,
        'max': 20,
        'detail': 'TLS certificate validity and expiry checks'
    }

    redir_points = 20 if not redirect_suspicious else 5
    score += redir_points
    breakdown['redirect_validation'] = {
        'points': redir_points,
        'max': 20,
        'detail': 'HTTP to HTTPS redirect behavior'
    }

    mitm_points = 25 if not mitm_warnings else max(0, 25 - min(len(mitm_warnings) * 8, 25))
    score += mitm_points
    breakdown['mitm_indicators'] = {
        'points': mitm_points,
        'max': 25,
        'detail': 'MITM indicators from SSL/redirect/connectivity checks'
    }

    dns_points = 15
    if dns_suspicious:
        dns_points -= 10
    if dns_trusted_mismatch:
        # low-weight signal only; mismatch is not direct proof of attack
        dns_points -= 2
    dns_points = max(0, dns_points)
    score += dns_points
    breakdown['dns_health'] = {
        'points': dns_points,
        'max': 15,
        'detail': 'DNS consistency and trusted resolver comparison (low weight)'
    }

    # Additional penalties from strong indicators (requested behavior)
    failed_ssl = sum(1 for r in ssl_results if not r.get('valid'))
    if failed_ssl > 0:
        score -= 30
    if redirect_suspicious:
        score -= 25
    if dns_suspicious:
        score -= 10

    # Captive portal is informative; low impact to avoid false positives.
    portal_points = 5 if not captive_portal else 2
    score += portal_points
    breakdown['portal_check'] = {'points': portal_points, 'max': 5, 'detail': 'Captive portal check (informational)'}

    return max(0, min(100, score)), breakdown


def classify_risk(score, strong_indicators=0):
    # Do not mark dangerous on a single issue.
    if score < 40 and strong_indicators >= 2:
        return 'Dangerous', 'red'
    if score >= 80:
        return 'Safe', 'green'
    if score >= 60:
        return 'Moderate', 'cyan'
    if score >= 40:
        return 'Risky', 'yellow'
    return 'Risky', 'yellow'


def calculate_confidence(https_results, ssl_results, dns_results, redirect_results, portal_details):
    completed = [
        len(https_results) > 0,
        len(ssl_results) > 0,
        len(dns_results) > 0,
        len(redirect_results) > 0,
        len(portal_details) > 0,
    ]
    if all(completed):
        return 'High'
    if sum(1 for x in completed if x) >= 3:
        return 'Medium'
    return 'Low'


def generate_recommendations(score, captive_portal, dns_suspicious,
                              failed_ssl_count, redirect_suspicious, mitm_warnings):
    recs = []
    if score < 85:
        recs.append('Use a trusted VPN to encrypt all traffic on this network')
    if captive_portal:
        recs.append('Avoid entering credentials on captive portal pages — they may be spoofed')
    if dns_suspicious:
        recs.append('Enable encrypted DNS (DoH/DoT) — try Cloudflare 1.1.1.1 or Google 8.8.8.8')
    if failed_ssl_count > 0:
        recs.append('Do NOT access banking or sensitive accounts on this network')
        recs.append('SSL certificates failing — your encrypted traffic may be intercepted')
    if redirect_suspicious:
        recs.append('HTTP traffic not properly upgraded to HTTPS — avoid unencrypted sites')
    if mitm_warnings:
        recs.append('MITM indicators detected (SSL/redirect/connectivity) — avoid sensitive logins')
    if score < 40:
        recs.append('Disconnect immediately and switch to mobile data')
        recs.append('Change passwords for accounts accessed on this network')
    if score >= 85:
        recs.append('Network appears safe — a VPN still adds an extra layer of privacy')
        recs.append('Keep your device firewall active and software updated')
    return recs

# ── PDF Generator ────────────────────────────────────────────────────────────

def generate_pdf_report(scan_data):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib           import colors
    from reportlab.lib.styles    import ParagraphStyle
    from reportlab.lib.units     import cm
    from reportlab.platypus      import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
    from reportlab.lib.enums     import TA_CENTER

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm,  bottomMargin=2*cm)

    C_BG   = colors.HexColor('#111827')
    C_CYAN = colors.HexColor('#00c9b1')
    C_GREY = colors.HexColor('#6b7280')
    C_LT   = colors.HexColor('#e5e7eb')
    C_ROW  = colors.HexColor('#1a2539')
    color_map = {'green': colors.HexColor('#00c853'),
                 'yellow':colors.HexColor('#ffd600'),
                 'red':   colors.HexColor('#ff1744')}
    sc = color_map.get(scan_data.get('color','green'), C_CYAN)

    def P(name, **kw): return ParagraphStyle(name, **kw)
    S_H1  = P('h1', fontName='Helvetica-Bold',  fontSize=20, textColor=colors.white, spaceAfter=2)
    S_SUB = P('sub',fontName='Helvetica',        fontSize=8,  textColor=C_GREY,  spaceAfter=2)
    S_SEC = P('sec',fontName='Helvetica-Bold',   fontSize=11, textColor=C_CYAN,  spaceBefore=12, spaceAfter=6)
    S_BOD = P('bod',fontName='Helvetica',        fontSize=9,  textColor=C_LT,    leading=13)
    S_REC = P('rec',fontName='Helvetica',        fontSize=9,  textColor=C_LT,    leading=13, leftIndent=6)
    S_WRN = P('wrn',fontName='Helvetica',        fontSize=9,  textColor=colors.HexColor('#ff1744'), leading=13)
    S_FTR = P('ftr',fontName='Helvetica',        fontSize=7,  textColor=C_GREY,  alignment=TA_CENTER)

    net    = scan_data.get('network_info', {})
    score  = scan_data.get('risk_score', 0)
    status = scan_data.get('status',     'Unknown')
    ts     = scan_data.get('timestamp',  '')
    sid    = scan_data.get('scan_id',    '-')

    def tbl_style(header_color=C_CYAN):
        return TableStyle([
            ('BACKGROUND',   (0,0),(-1,0),  header_color),
            ('TEXTCOLOR',    (0,0),(-1,0),  colors.HexColor('#0a0a0f')),
            ('FONTNAME',     (0,0),(-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',     (0,0),(-1,0),  9),
            ('BACKGROUND',   (0,1),(-1,-1), C_BG),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_BG, C_ROW]),
            ('TEXTCOLOR',    (0,1),(-1,-1), C_LT),
            ('FONTSIZE',     (0,1),(-1,-1), 9),
            ('BOX',          (0,0),(-1,-1), 0.5, C_GREY),
            ('INNERGRID',    (0,0),(-1,-1), 0.3, colors.HexColor('#1f2d3d')),
            ('LEFTPADDING',  (0,0),(-1,-1), 8),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('TOPPADDING',   (0,0),(-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ])

    story = []
    story.append(Paragraph('WiFiGuard Security Report', S_H1))
    story.append(Paragraph(f'Scan #{sid}  |  {ts}', S_SUB))
    story.append(HRFlowable(width='100%', thickness=1, color=C_CYAN, spaceAfter=8))

    # Status row
    st_tbl = Table([[
        Paragraph(f'Status: {status}',      P('s1',fontName='Helvetica-Bold',fontSize=13,textColor=sc)),
        Paragraph(f'Score: {score} / 100',  P('s2',fontName='Helvetica-Bold',fontSize=13,textColor=sc)),
    ]], colWidths=['55%','45%'])
    st_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), C_BG),
        ('BOX',(0,0),(-1,-1),1,sc),
        ('LEFTPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),10),
        ('BOTTOMPADDING',(0,0),(-1,-1),10),
    ]))
    story.append(st_tbl); story.append(Spacer(1,10))

    # Network info
    story.append(Paragraph('Network Information', S_SEC))
    rows = [['Field','Value'],
            ['Public IP', net.get('public_ip','—')], ['City',   net.get('city','—')],
            ['Region',    net.get('region','—')],     ['Country',net.get('country','—')],
            ['ISP / Org', net.get('isp','—')],        ['Timezone',net.get('timezone','—')]]
    t = Table(rows, colWidths=['30%','70%']); t.setStyle(tbl_style())
    story.append(t); story.append(Spacer(1,8))

    # Score breakdown
    story.append(Paragraph('Score Breakdown', S_SEC))
    bd = scan_data.get('breakdown', {})
    labels = [('https_connectivity','HTTPS Connectivity'),('ssl_validation','SSL Validation'),
              ('dns_health','DNS Health'),('portal_check','Captive Portal'),
              ('redirect_validation','HTTP Redirects'),('mitm_indicators','MITM Indicators')]
    bd_rows = [['Check','Score','Detail']]
    for key, label in labels:
        e = bd.get(key, {})
        bd_rows.append([label, f'{e.get("points",0)}/{e.get("max",0)}', e.get('detail','—')])
    bd_rows.append(['FINAL SCORE', str(score), f'{status} Network'])
    t2 = Table(bd_rows, colWidths=['32%','14%','54%'])
    ts2 = tbl_style(); ts2.add('BACKGROUND',(0,len(bd_rows)-1),(-1,-1),colors.HexColor('#0d1f12'))
    ts2.add('TEXTCOLOR', (0,len(bd_rows)-1),(-1,-1),sc)
    ts2.add('FONTNAME',  (0,len(bd_rows)-1),(-1,-1),'Helvetica-Bold')
    ts2.add('ALIGN',(1,0),(1,-1),'CENTER')
    t2.setStyle(ts2); story.append(t2); story.append(Spacer(1,8))

    mitm = scan_data.get('mitm_warnings',[])
    if mitm:
        story.append(Paragraph('MITM Risk Indicators', S_SEC))
        for w in mitm: story.append(Paragraph(f'  ⚠  {w}', S_WRN))
        story.append(Spacer(1,6))

    recs = scan_data.get('recommendations',[])
    if recs:
        story.append(Paragraph('Security Recommendations', S_SEC))
        for i, r in enumerate(recs,1): story.append(Paragraph(f'{i}.  {r}', S_REC))
        story.append(Spacer(1,6))

    story.append(HRFlowable(width='100%',thickness=0.5,color=C_GREY,spaceBefore=8))
    story.append(Paragraph('WiFiGuard v2.0  —  For educational use only. '
                            'Not a substitute for professional security auditing.', S_FTR))
    doc.build(story)
    buf.seek(0); return buf.read()


def generate_website_pdf_report(site_data: dict):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    C_BG = colors.HexColor('#111827')
    C_CYAN = colors.HexColor('#00c9b1')
    C_GREY = colors.HexColor('#6b7280')
    C_LT = colors.HexColor('#e5e7eb')
    C_ROW = colors.HexColor('#1a2539')
    color_map = {'green': colors.HexColor('#00c853'),
                 'yellow': colors.HexColor('#ffd600'),
                 'red': colors.HexColor('#ff1744')}
    sc = color_map.get(site_data.get('color', 'green'), C_CYAN)

    def P(name, **kw): return ParagraphStyle(name, **kw)
    S_H1 = P('h1', fontName='Helvetica-Bold', fontSize=20, textColor=colors.white, spaceAfter=2)
    S_SUB = P('sub', fontName='Helvetica', fontSize=8, textColor=C_GREY, spaceAfter=2)
    S_SEC = P('sec', fontName='Helvetica-Bold', fontSize=11, textColor=C_CYAN, spaceBefore=12, spaceAfter=6)
    S_BOD = P('bod', fontName='Helvetica', fontSize=9, textColor=C_LT, leading=13)
    S_FTR = P('ftr', fontName='Helvetica', fontSize=7, textColor=C_GREY, alignment=TA_CENTER)

    def tbl_style(header_color=C_CYAN):
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), header_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0a0a0f')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BACKGROUND', (0, 1), (-1, -1), C_BG),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_BG, C_ROW]),
            ('TEXTCOLOR', (0, 1), (-1, -1), C_LT),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOX', (0, 0), (-1, -1), 0.5, C_GREY),
            ('INNERGRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#1f2d3d')),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ])

    url_in = site_data.get('input_url', '—')
    url_final = site_data.get('final_url', '—')
    score = int(site_data.get('risk_score', 0) or 0)
    status = site_data.get('status', 'Unknown')
    ts = site_data.get('timestamp', '')

    story = []
    story.append(Paragraph('WiFiGuard Website Security Report', S_H1))
    story.append(Paragraph(f'{ts}', S_SUB))
    story.append(HRFlowable(width='100%', thickness=1, color=C_CYAN, spaceAfter=8))

    st_tbl = Table([[
        Paragraph(f'Status: {status}', P('s1', fontName='Helvetica-Bold', fontSize=13, textColor=sc)),
        Paragraph(f'Score: {score} / 100', P('s2', fontName='Helvetica-Bold', fontSize=13, textColor=sc)),
    ]], colWidths=['55%', '45%'])
    st_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_BG),
        ('BOX', (0, 0), (-1, -1), 1, sc),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(st_tbl)
    story.append(Spacer(1, 10))

    story.append(Paragraph('Target', S_SEC))
    trows = [['Field', 'Value'],
             ['Input URL', url_in],
             ['Final URL', url_final],
             ['HTTPS Final', 'Yes' if site_data.get('https_final') else 'No'],
             ['HTTPS Enforced', 'Yes' if site_data.get('https_enforced') else 'No'],
             ['Redirect Count', str(site_data.get('redirect_count', 0) or 0)]]
    t = Table(trows, colWidths=['30%', '70%'])
    t.setStyle(tbl_style())
    story.append(t)
    story.append(Spacer(1, 8))

    story.append(Paragraph('SSL Certificate', S_SEC))
    ssl_d = site_data.get('ssl', {}) or {}
    srows = [['Field', 'Value'],
             ['Valid', 'Yes' if ssl_d.get('valid') else 'No'],
             ['Expires', ssl_d.get('expires', '—') or '—'],
             ['Days Until Expiry', str(ssl_d.get('days_until_expiry')) if ssl_d.get('days_until_expiry') is not None else '—'],
             ['Error', (ssl_d.get('error') or '')[:120] or '—']]
    st = Table(srows, colWidths=['30%', '70%'])
    st.setStyle(tbl_style())
    story.append(st)
    story.append(Spacer(1, 8))

    story.append(Paragraph('Security Headers (Final Response)', S_SEC))
    hchecks = site_data.get('header_checks', []) or []
    hrows = [['Header', 'Present', 'Risk', 'Explanation']]
    for hc in hchecks:
        hrows.append([
            hc.get('name', '—'),
            'Yes' if hc.get('present') else 'No',
            hc.get('risk', '—'),
            (hc.get('explanation') or '—')[:160]
        ])
    ht = Table(hrows, colWidths=['28%', '12%', '12%', '48%'])
    ht.setStyle(tbl_style())
    story.append(ht)
    story.append(Spacer(1, 8))

    story.append(Paragraph('Redirect Chain', S_SEC))
    rchain = site_data.get('redirect_chain', []) or []
    rrows = [['Step', 'Status', 'URL']]
    for i, r in enumerate(rchain[:12], 1):
        rrows.append([str(i), str(r.get('status', '—')), (r.get('url', '—') or '—')[:110]])
    rt = Table(rrows, colWidths=['10%', '12%', '78%'])
    rt.setStyle(tbl_style())
    story.append(rt)

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_GREY, spaceBefore=8))
    story.append(Paragraph(
        'Disclaimer: This analysis is based on heuristic and connectivity checks. It does not guarantee complete network security.',
        S_FTR
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()

# ── Website Scanner ──────────────────────────────────────────────────────────

def _website_redirect_chain(url: str, timeout: float = 6.0, max_hops: int = 8):
    def is_ip(s: str) -> bool:
        try:
            socket.inet_aton(s)
            return True
        except Exception:
            return False

    def resolve_ips(host: str):
        if not host:
            return []
        if is_ip(host):
            return [host]
        # Prefer system resolver; if it fails (e.g. captive DNS / local outage), fall back to trusted DNS.
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ips = list({i[4][0] for i in infos})
            if ips:
                return ips
        except Exception:
            pass
        try:
            return _dns_query_a_udp('8.8.8.8', host, timeout=2.0)
        except Exception:
            return []

    def fetch_once(current_url: str):
        parsed = urlparse(current_url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Only http/https URLs are allowed')
        host = parsed.hostname
        if not host:
            raise ValueError('URL hostname is missing')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'
        if parsed.query:
            path = f'{path}?{parsed.query}'

        # If the user enters `www.example.com` but `www` has no A record, many sites serve from the apex.
        candidates = [host]
        if host.startswith('www.'):
            candidates.append(host[4:])

        chosen_host = None
        ips = []
        for h in candidates:
            ips = resolve_ips(h)
            if ips:
                chosen_host = h
                break

        if not ips or not chosen_host:
            raise ValueError(f'Could not resolve hostname via system or trusted DNS: {host}')

        # Effective URL for redirect joining should use the hostname that we actually resolved.
        port_part = f':{parsed.port}' if parsed.port else ''
        effective_url = f'{parsed.scheme}://{chosen_host}{port_part}{path}'

        last_err = None
        for ip in ips[:3]:
            sock = None
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                if parsed.scheme == 'https':
                    # For redirect analysis we allow unverified TLS to still fetch headers.
                    ctx_unverified = ssl.create_default_context()
                    ctx_unverified.check_hostname = False
                    ctx_unverified.verify_mode = ssl.CERT_NONE
                    sock = ctx_unverified.wrap_socket(sock, server_hostname=chosen_host)

                req = (
                    f'GET {path} HTTP/1.1\r\n'
                    f'Host: {chosen_host}\r\n'
                    f'User-Agent: WiFiGuard/2.0\r\n'
                    f'Accept: */*\r\n'
                    f'Connection: close\r\n'
                    f'\r\n'
                ).encode('ascii', 'ignore')
                sock.sendall(req)

                # Manual HTTP header parsing to avoid platform-specific quirks.
                # We only need status code + response headers for redirects/security headers.
                raw = b''
                # Cap read size to prevent memory blowups on broken servers.
                max_header_bytes = 65536
                while b'\r\n\r\n' not in raw and len(raw) < max_header_bytes:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk

                if b'\r\n\r\n' not in raw:
                    raise ValueError('No HTTP headers received')

                header_blob, _body = raw.split(b'\r\n\r\n', 1)
                lines = header_blob.split(b'\r\n')
                status_line = lines[0].decode('iso-8859-1', 'ignore')
                parts = status_line.split(' ')
                status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

                headers = {}
                for ln in lines[1:]:
                    if b':' not in ln:
                        continue
                    k, v = ln.split(b':', 1)
                    k = k.decode('iso-8859-1', 'ignore').strip()
                    v = v.decode('iso-8859-1', 'ignore').strip()
                    # If repeated, concatenate.
                    if k in headers:
                        headers[k] = headers[k] + ', ' + v
                    else:
                        headers[k] = v

                try:
                    sock.close()
                except Exception:
                    pass
                return status, headers, effective_url
            except Exception as e:
                last_err = e
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
                continue
        raise last_err or ValueError('Fetch failed')

    chain = []
    current = url
    final_headers = {}
    for hop in range(max_hops):
        status, headers, effective_url = fetch_once(current)
        location = headers.get('Location')
        chain.append({'url': effective_url, 'status': status, 'location': location, 'final_url': None})

        # Follow redirects for common 3xx statuses with a Location header.
        if location and status in (301, 302, 303, 307, 308):
            current = urljoin(effective_url, location)
            continue

        final_url = effective_url
        final_headers = headers
        chain[-1]['final_url'] = final_url
        return chain, final_url, final_headers

    final_url = current
    return chain, final_url, final_headers


def website_security_scan(url: str):
    url_raw = (url or '').strip()
    if not url_raw:
        raise ValueError('URL is required')

    # Normalize user input to a URL we can request.
    has_scheme = url_raw.startswith(('http://', 'https://'))
    start_url = url_raw if has_scheme else f'http://{url_raw}'

    sess = requests.Session()
    sess.headers.update({'User-Agent': 'WiFiGuard/2.0'})

    def looks_like_dns_failure(err: Exception) -> bool:
        msg = str(err).lower()
        return ('failed to resolve' in msg) or ('name resolution' in msg) or ('getaddrinfo failed' in msg)

    def request_with_fallbacks():
        # Build hostname candidates (www -> apex) and scheme candidates (http/https when user omitted scheme).
        if has_scheme:
            parsed = urlparse(start_url)
            host = parsed.hostname or ''
            host_candidates = [host]
            if host.startswith('www.'):
                host_candidates.append(host[4:])
            scheme_candidates = [parsed.scheme]
            path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
            for h in host_candidates:
                if not h:
                    continue
                candidate_url = f'{parsed.scheme}://{h}{":" + str(parsed.port) if parsed.port else ""}{path}'
                try:
                    return sess.get(candidate_url, allow_redirects=True, timeout=10)
                except requests.RequestException as e:
                    if looks_like_dns_failure(e):
                        continue
                    raise
            raise ValueError(f'Could not resolve hostname: {host}')
        else:
            parsed = urlparse('http://' + url_raw)
            host = parsed.hostname or ''
            host_candidates = [host]
            if host.startswith('www.'):
                host_candidates.append(host[4:])
            scheme_candidates = ['http', 'https']
            path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
            last_err = None
            for h in host_candidates:
                if not h:
                    continue
                for sch in scheme_candidates:
                    candidate_url = f'{sch}://{h}{path}'
                    try:
                        return sess.get(candidate_url, allow_redirects=True, timeout=10)
                    except requests.RequestException as e:
                        last_err = e
                        # On DNS failure, try next host candidate.
                        if looks_like_dns_failure(e):
                            break
                        # Otherwise try next scheme (http->https) before giving up.
                        continue
            raise ValueError(str(last_err) if last_err else 'Request failed')

    try:
        resp = request_with_fallbacks()
    except requests.RequestException as e:
        raise ValueError(str(e)) from e

    final_url = resp.url
    final_parsed = urlparse(final_url)
    https_final = final_parsed.scheme.lower() == 'https'

    # Redirect chain
    chain = [{'url': r.url, 'status': r.status_code, 'location': r.headers.get('Location'), 'final_url': None}
             for r in (resp.history or [])]
    chain.append({'url': final_url, 'status': resp.status_code, 'location': None, 'final_url': final_url})

    # HTTPS enforcement
    https_enforced = False
    if start_url.startswith('http://') and https_final:
        https_enforced = True
    # Also consider "no scheme" as enforced if http -> https happened in history.
    if not has_scheme and https_final and any(h.url.startswith('http://') for h in (resp.history or [])):
        https_enforced = True

    # Suspicious redirect heuristics
    redirects_count = len(resp.history or [])
    domains = []
    for r in (resp.history or []):
        try:
            domains.append(urlparse(r.url).hostname or '')
        except Exception:
            pass
    domains.append(final_parsed.hostname or '')
    unique_domains = [d for d in dict.fromkeys([d.lower() for d in domains if d])]
    cross_domain = len(unique_domains) > 1
    downgrade = any(urlparse(h.url).scheme == 'https' for h in (resp.history or [])) and (final_parsed.scheme == 'http')

    # Final response headers (case-insensitive via requests)
    hdr = {k.lower(): v for k, v in (resp.headers or {}).items()}
    header_keys = {
        'content-security-policy': 'Content-Security-Policy',
        'strict-transport-security': 'Strict-Transport-Security',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy',
    }
    present_headers = {pretty: hdr.get(low) for low, pretty in header_keys.items() if hdr.get(low)}
    missing_headers = [pretty for low, pretty in header_keys.items() if not hdr.get(low)]

    header_explain = {
        'Content-Security-Policy': 'Missing Content-Security-Policy increases risk of XSS and content injection.',
        'Strict-Transport-Security': 'Missing HSTS allows SSL stripping and weaker HTTPS enforcement.',
        'X-Frame-Options': 'Missing X-Frame-Options increases risk of clickjacking.',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options can enable MIME sniffing attacks.',
        'Referrer-Policy': 'Missing Referrer-Policy may leak sensitive URLs via the Referer header.',
        'Permissions-Policy': 'Missing Permissions-Policy can allow unnecessary browser features.',
    }

    # SSL certificate validation + expiry (real TLS handshake)
    ssl_info = {'valid': None, 'error': None, 'expires': None, 'days_until_expiry': None}
    if https_final and final_parsed.hostname:
        host = final_parsed.hostname
        port = final_parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=7), server_hostname=host)
            cert = conn.getpeercert()
            conn.close()
            exp = cert.get('notAfter', '')
            secs = ssl.cert_time_to_seconds(exp) if exp else None
            days = round((secs - time.time()) / 86400) if secs else None
            ssl_info.update({'valid': True, 'expires': exp, 'days_until_expiry': days})
        except ssl.SSLCertVerificationError as e:
            ssl_info.update({'valid': False, 'error': 'Certificate verification failed', 'detail': str(e)[:160]})
        except Exception as e:
            ssl_info.update({'valid': False, 'error': str(e)[:160]})
    else:
        ssl_info.update({'valid': False, 'error': 'Final URL is not HTTPS'})

    # Scoring (start 100)
    score = 100
    issues = []

    if not https_final:
        score -= 35
        issues.append({'key': 'https', 'risk': 'High', 'status': 'Fail',
                       'explanation': 'Site does not use HTTPS on the final destination.'})
    else:
        issues.append({'key': 'https', 'risk': 'Low', 'status': 'Pass',
                       'explanation': 'Final destination uses HTTPS.'})

    if start_url.startswith('http://') and not https_enforced:
        score -= 15
        issues.append({'key': 'https_enforcement', 'risk': 'High', 'status': 'Fail',
                       'explanation': 'HTTP is not cleanly redirected to HTTPS (risk of SSL stripping).'})
    elif start_url.startswith('http://'):
        issues.append({'key': 'https_enforcement', 'risk': 'Low', 'status': 'Pass',
                       'explanation': 'HTTP is redirected to HTTPS.'})

    if ssl_info.get('valid') is False:
        score -= 25
        issues.append({'key': 'ssl', 'risk': 'High', 'status': 'Fail',
                       'explanation': 'TLS certificate validation failed (possible misconfiguration or interception).'})
    else:
        issues.append({'key': 'ssl', 'risk': 'Low', 'status': 'Pass',
                       'explanation': 'TLS certificate validated successfully.'})

    if redirects_count > 3:
        score -= 10
        issues.append({'key': 'redirects', 'risk': 'Medium', 'status': 'Fail',
                       'explanation': f'High redirect count ({redirects_count}) can indicate tracking chains or misconfiguration.'})
    else:
        issues.append({'key': 'redirects', 'risk': 'Low', 'status': 'Pass',
                       'explanation': f'Redirect count is {redirects_count}.'})

    if cross_domain:
        score -= 8
        issues.append({'key': 'redirect_domain', 'risk': 'Medium', 'status': 'Fail',
                       'explanation': f'Redirects cross domains ({", ".join(unique_domains[:3])}{"…" if len(unique_domains)>3 else ""}). Review for phishing risk.'})

    if downgrade:
        score -= 25
        issues.append({'key': 'redirect_downgrade', 'risk': 'High', 'status': 'Fail',
                       'explanation': 'Redirect chain downgrades from HTTPS to HTTP.'})

    # Header penalties (do not fake; based on final response headers only)
    if 'Content-Security-Policy' in missing_headers:
        score -= 20
    if https_final and 'Strict-Transport-Security' in missing_headers:
        score -= 20
    if 'X-Frame-Options' in missing_headers:
        score -= 10
    if 'X-Content-Type-Options' in missing_headers:
        score -= 8
    if 'Referrer-Policy' in missing_headers:
        score -= 5
    if 'Permissions-Policy' in missing_headers:
        score -= 5

    header_checks = []
    for low, pretty in header_keys.items():
        present = bool(hdr.get(low))
        header_checks.append({
            'name': pretty,
            'present': present,
            'value': (hdr.get(low) or '')[:220],
            'risk': 'High' if pretty in ('Content-Security-Policy', 'Strict-Transport-Security') else ('Medium' if pretty in ('X-Frame-Options', 'X-Content-Type-Options') else 'Low'),
            'explanation': 'Present on final response.' if present else header_explain.get(pretty, 'Missing security header.'),
        })

    score = max(0, score)
    status, color = classify_risk(score)

    return {
        'input_url': url_raw if has_scheme else url_raw,
        'start_url': start_url,
        'final_url': final_url,
        'https_final': https_final,
        'https_enforced': https_enforced,
        'ssl': ssl_info,
        'redirect_chain': chain,
        'redirect_count': redirects_count,
        'cross_domain_redirect': cross_domain,
        'security_headers': present_headers,
        'missing_security_headers': missing_headers,
        'header_checks': header_checks,
        'issues': issues,
        'risk_score': score,
        'status': status,
        'color': color,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'disclaimer': 'This analysis is based on heuristic and connectivity checks. It does not guarantee complete network security.',
    }

# ── Main Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/website')
def website():
    return render_template('website.html')


@app.route('/history')
def history_page():
    return render_template('history.html')


@app.route('/about')
def about():
    return render_template('about.html')


def _build_scan_result(scan_mode, network_info, local_ip, https_results, ssl_results, dns_results,
                       dns_suspicious, dns_rep_results, dns_trusted_mismatch, portal_details,
                       captive_portal, redirect_results, redirect_suspicious, mitm_warnings,
                       devices, gateway, scan_start):
    failed_ssl_count = sum(1 for r in ssl_results if not r.get('valid'))
    score, breakdown = calculate_risk_score(
        https_results, ssl_results, dns_suspicious,
        captive_portal, redirect_suspicious, mitm_warnings,
        dns_trusted_mismatch=dns_trusted_mismatch,
    )
    strong_indicators = 0
    if failed_ssl_count > 0:
        strong_indicators += 1
    if redirect_suspicious:
        strong_indicators += 1
    if len(mitm_warnings) >= 2:
        strong_indicators += 1
    status, color = classify_risk(score, strong_indicators=strong_indicators)
    confidence = calculate_confidence(https_results, ssl_results, dns_results, redirect_results, portal_details)
    recommendations = generate_recommendations(score, captive_portal, dns_suspicious,
                                               failed_ssl_count, redirect_suspicious, mitm_warnings)
    scan_duration = round(time.time() - scan_start, 2)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    gateway_changed = False
    if scan_mode == 'full':
        gateway_state_path = os.path.join(DATA_DIR, 'gateway_state.json')
        prev_gw_raw = _read_json_file(gateway_state_path)
        prev_gw = prev_gw_raw if isinstance(prev_gw_raw, dict) else {}
        prev_mac = prev_gw.get('mac')
        gateway_changed = bool(prev_mac and gateway.get('mac') and prev_mac != gateway.get('mac'))
        _write_json_file(gateway_state_path, {'mac': gateway.get('mac'), 'ip': gateway.get('ip'), 'timestamp': timestamp})

    new_keys = set()
    if scan_mode == 'full':
        device_state_path = os.path.join(DATA_DIR, 'devices_state.json')
        prev_dev_raw = _read_json_file(device_state_path)
        prev_devices = prev_dev_raw.get('devices', []) if isinstance(prev_dev_raw, dict) else []
        prev_keys = {(d.get('ip'), d.get('mac')) for d in prev_devices if isinstance(d, dict)}
        curr_keys = {(d.get('ip'), d.get('mac')) for d in devices if isinstance(d, dict)}
        new_keys = curr_keys - prev_keys
        for d in devices:
            key = (d.get('ip'), d.get('mac'))
            d['is_new'] = key in new_keys
            d['is_unknown'] = d.get('vendor') in ('Unknown', 'Unidentified Device')
            d['status_tag'] = 'new' if d['is_new'] else ('unknown' if d['is_unknown'] else 'known')
        _write_json_file(device_state_path, {'timestamp': timestamp, 'devices': devices})

    findings = []
    if failed_ssl_count:
        findings.append('SSL certificate validation failed on one or more test domains.')
    if redirect_suspicious:
        findings.append('Some HTTP endpoints did not upgrade cleanly to HTTPS.')
    if dns_suspicious:
        findings.append('DNS resolution contains unexpected ranges for known domains (low confidence signal).')
    if dns_trusted_mismatch:
        findings.append('Resolver output differs from trusted resolver for some domains (not direct proof of attack).')
    if captive_portal:
        findings.append('Captive portal behavior detected; this is common on guest/public networks.')
    if mitm_warnings:
        findings.extend(mitm_warnings[:2])
    if gateway_changed:
        findings.append('Default gateway MAC changed from previous scan. Verify router/network authenticity.')
    if new_keys:
        findings.append(f'New device detected on your network ({len(new_keys)}).')
    if scan_mode == 'quick':
        findings.append('Device scan skipped (Quick mode).')

    devices_payload = {
        'count': len(devices),
        'new_count': len(new_keys),
        'scan_mode': scan_mode,
        'list': devices,
        'total_devices': len(devices),
        'disclaimer': 'Device detection is based on ARP cache and active probing. Some devices may not appear if inactive or blocked by firewall.'
    }
    if scan_mode == 'quick':
        devices_payload['skipped'] = True
        devices_payload['message'] = 'Device scan skipped (Quick mode)'
    elif len(devices) == 0:
        devices_payload['message'] = 'Device scan not available in this environment'

    return {
        'mode': scan_mode,
        'timestamp': timestamp,
        'client_ip': network_info['public_ip'],
        'network_info': {**network_info, 'local_ip': local_ip},
        'scan_duration_sec': scan_duration,
        'risk_score': score,
        'score': score,
        'status': status,
        'color': color,
        'confidence': confidence,
        'findings': findings,
        'breakdown': breakdown,
        'checks': {'https': https_results, 'ssl': ssl_results, 'dns': dns_results,
                   'captive_portal': portal_details, 'redirects': redirect_results},
        'mitm_warnings': mitm_warnings,
        'recommendations': recommendations,
        'dns_suspicious': dns_suspicious,
        'captive_portal_detected': captive_portal,
        'redirect_suspicious': redirect_suspicious,
        'dns_reputation': {'trusted_dns': '8.8.8.8', 'results': dns_rep_results, 'mismatch': dns_trusted_mismatch},
        'devices': devices_payload,
        'gateway': {'ip': gateway.get('ip'), 'mac': gateway.get('mac'), 'changed': gateway_changed},
        'disclaimer': 'This analysis is based on heuristic and connectivity checks. It does not guarantee complete network security.',
    }


def run_quick_scan(client_ip: str):
    scan_start = time.time()
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {
            ex.submit(fetch_network_info, client_ip): 'network_info',
            ex.submit(check_https_connectivity, ['https://www.google.com', 'https://www.cloudflare.com']): 'https',
            ex.submit(check_ssl_certificates, [('www.google.com', 443)]): 'ssl',
            ex.submit(check_dns_behavior, {'google.com': ['142.250.', '172.217.', '216.58.', '74.125.']}): 'dns',
            ex.submit(get_default_gateway_info): 'gateway',
            ex.submit(get_local_ip): 'local_ip',
        }
        out = {futs[f]: f.result() for f in as_completed(futs)}

    network_info = out['network_info']
    https_results = out['https']
    ssl_results = out['ssl']
    dns_results, dns_suspicious = out['dns']
    gateway = out['gateway']
    local_ip = out['local_ip']

    # Quick mode skips heavy checks by design.
    redirect_results, redirect_suspicious = [], False
    portal_details, captive_portal = [], False
    dns_rep_results, dns_trusted_mismatch = [], False
    mitm_warnings = check_mitm_heuristics(ssl_results, dns_results, https_results)
    devices = []

    return _build_scan_result('quick', network_info, local_ip, https_results, ssl_results, dns_results,
                              dns_suspicious, dns_rep_results, dns_trusted_mismatch, portal_details,
                              captive_portal, redirect_results, redirect_suspicious, mitm_warnings,
                              devices, gateway, scan_start)


def run_full_scan(client_ip: str):
    scan_start = time.time()
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {
            ex.submit(fetch_network_info, client_ip): 'network_info',
            ex.submit(check_https_connectivity, ['https://www.google.com', 'https://www.cloudflare.com', 'https://www.github.com']): 'https',
            ex.submit(check_ssl_certificates, [('www.google.com', 443), ('www.cloudflare.com', 443), ('www.github.com', 443)]): 'ssl',
            ex.submit(check_dns_behavior): 'dns',
            ex.submit(check_dns_reputation_with_trusted): 'dns_rep',
            ex.submit(check_captive_portal): 'portal',
            ex.submit(check_suspicious_redirects): 'redirects',
            ex.submit(get_default_gateway_info): 'gateway',
            ex.submit(get_local_ip): 'local_ip',
        }
        out = {futs[f]: f.result() for f in as_completed(futs)}

    network_info = out['network_info']
    https_results = out['https']
    ssl_results = out['ssl']
    dns_results, dns_suspicious = out['dns']
    dns_rep_results, dns_trusted_mismatch = out['dns_rep']
    portal_details, captive_portal = out['portal']
    redirect_results, redirect_suspicious = out['redirects']
    gateway = out['gateway']
    local_ip = out['local_ip']
    devices = scan_local_devices_from_arp(local_ip=local_ip, gateway_ip=gateway.get('ip'), mode='full')
    mitm_warnings = check_mitm_heuristics(ssl_results, dns_results, https_results)

    return _build_scan_result('full', network_info, local_ip, https_results, ssl_results, dns_results,
                              dns_suspicious, dns_rep_results, dns_trusted_mismatch, portal_details,
                              captive_portal, redirect_results, redirect_suspicious, mitm_warnings,
                              devices, gateway, scan_start)


@app.route('/scan', methods=['POST'])
def scan():
    body = request.get_json(silent=True) or {}
    client_ip = body.get('client_ip') or get_client_ip(request)
    scan_mode = (body.get('scan_mode') or 'quick').strip().lower()
    if scan_mode not in ('quick', 'full'):
        scan_mode = 'quick'
    try:
        result = run_quick_scan(client_ip) if scan_mode == 'quick' else run_full_scan(client_ip)
        scan_id = int(time.time() * 1000)
        result['scan_id'] = scan_id
        _append_scan_log({
            'id': scan_id,
            'created_at': datetime.datetime.utcnow().isoformat(),
            'timestamp': result.get('timestamp'),
            'public_ip': result.get('network_info', {}).get('public_ip'),
            'city': result.get('network_info', {}).get('city'),
            'country': result.get('network_info', {}).get('country'),
            'isp': result.get('network_info', {}).get('isp'),
            'risk_score': result.get('risk_score'),
            'status': result.get('status'),
            'color': result.get('color'),
            'duration': result.get('scan_duration_sec'),
            'result': result,
        }, limit=50)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/history')
def api_history():
    delete_old_scans()
    log = _load_scan_log()
    history = [{
        'id': h.get('id'),
        'timestamp': h.get('timestamp'),
        'public_ip': h.get('public_ip'),
        'city': h.get('city'),
        'country': h.get('country'),
        'isp': h.get('isp'),
        'risk_score': h.get('risk_score'),
        'status': h.get('status'),
        'color': h.get('color'),
        'duration': h.get('duration'),
    } for h in log if isinstance(h, dict)]
    return jsonify({'success': True, 'history': history})


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    delete_old_scans()
    log = _load_scan_log()
    for h in log:
        if isinstance(h, dict) and h.get('id') == scan_id:
            data = h.get('result') or {}
            if isinstance(data, dict):
                data['scan_id'] = scan_id
            return jsonify({'success': True, 'data': data})
    return jsonify({'success': False, 'error': 'Scan not found'}), 404


@app.route('/api/website-scan', methods=['POST'])
def api_website_scan():
    body = request.get_json(silent=True) or {}
    url = body.get('url', '')
    try:
        data = website_security_scan(url)
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/website-report', methods=['POST'])
def api_website_report():
    body = request.get_json(silent=True) or {}
    url = body.get('url', '')
    try:
        data = website_security_scan(url)
        pdf = generate_website_pdf_report(data)
        ts = (data.get('timestamp') or '').replace(':', '').replace(' ', '_').replace('-', '')
        safe_host = (urlparse(data.get('final_url', '')).hostname or 'website').replace('.', '_')
        fname = f'WiFiGuard_Website_Report_{safe_host}_{ts or "scan"}.pdf'
        return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                         as_attachment=True, download_name=fname)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/report/<int:scan_id>')
def download_report(scan_id):
    delete_old_scans()
    log = _load_scan_log()
    for h in log:
        if isinstance(h, dict) and h.get('id') == scan_id:
            data = h.get('result') or {}
            if not isinstance(data, dict):
                break
            try:
                data = dict(data)
                data['scan_id'] = scan_id
                pdf = generate_pdf_report(data)
                ts = h.get('timestamp', '').replace(':', '').replace(' ', '_').replace('-', '')
                fname = f'WiFiGuard_Report_{scan_id}_{ts or "scan"}.pdf'
                return send_file(io.BytesIO(pdf), mimetype='application/pdf',
                                 as_attachment=True, download_name=fname)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    abort(404)


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'WiFiGuard', 'version': '2.0.0'})

start_history_cleanup_thread()

if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); local_ip = s.getsockname()[0]; s.close()
    except Exception:
        local_ip = '127.0.0.1'
    print(f'\n{"="*58}\n  WiFiGuard v2.0\n  Desktop: http://127.0.0.1:5000\n  Mobile:  http://{local_ip}:5000\n{"="*58}\n')
    app.run(host='0.0.0.0', port=5000, debug=False)
