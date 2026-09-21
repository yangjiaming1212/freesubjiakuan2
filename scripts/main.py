import os
import re
import json
import time
import uuid
import ipaddress
import zipfile
import base64
import shutil
import socket
import subprocess
import urllib.request
import urllib.parse
import hashlib
import threading
import requests
import yaml
import maxminddb
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SOURCE_URLS = [
    "https://wild-cloud-9893.heleimail.workers.dev",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://open.heleimail.workers.dev/",
    "https://www.ermao.net/sub/v2ray/ermao.net",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/Baarcuda/vpn-configs/master/top100.txt",
    "https://raw.githubusercontent.com/Baarcuda/vpn-configs/master/top100-vless.txt",
]

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

MAX_FETCH_WORKERS = 8
MAX_TEST_WORKERS = 16
TEST_TIMEOUT = 7
MIN_PUBLISH_NODES = 3

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)",
    "JP": "日本 (Japan)", "SG": "新加坡 (Singapore)",
    "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)",
    "CA": "加拿大 (Canada)", "FR": "法国 (France)",
    "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)",
    "IT": "意大利 (Italy)", "ES": "西班牙 (Spain)",
    "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "OTHER": "其他地区 (Other)",
}

DATACENTER_ASNS = {
    13335, 16509, 14618, 15169, 396982, 8075, 24940, 16276,
    14061, 31898, 63949, 45102, 132203, 20473, 60068, 55081,
    197540, 51167, 8560, 42708, 201814, 49981, 212238, 46652,
    141995, 200019, 136907, 39351, 9009, 174, 3356, 1299, 2914,
    199180, 202051, 62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373,
}

IDC_KEYWORDS = (
    "hosting", "datacenter", "data center", "cloud", "server", "vps",
    "dedicated", "compute", "colo", "digitalocean", "linode", "ovh",
    "hetzner", "choopa", "vultr", "alibaba", "tencent", "amazon", "aws",
    "google cloud", "microsoft azure", "oracle cloud", "fastly",
    "cloudflare", "akamai", "m247", "leaseweb", "contabo", "cogent",
    "zenlayer", "ucloud", "hostkey", "selectel", "quadranet", "buyvm",
    "scaleway", "oracle", "aliyun",
)

RESIDENTIAL_KEYWORDS = (
    "broadband", "residential", "dynamic", "pppoe", "cust", "dial",
    "user", "home", "ftth", "cable", "dsl", "adsl", "consumer",
    "telecom", "telecommunications", "communications", "internet",
    "isp", "mobile", "wireless", "fiber", "fibre", "chunghwa",
    "hinet", "cht", "taiwan fixed network", "kbro", "far eastone",
    "tfn", "hkbn", "hong kong broadband", "pccw", "hkt", "hgc",
    "smartone", "so-net", "kddi", "softbank", "ocn", "plala",
    "sk broadband", "korea telecom", "comcast", "charter", "at&t",
    "verizon", "spectrum", "cox", "vodafone", "deutsche telekom",
    "telekom", "orange", "bt-central", "virgin media",
)

CLOUDFLARE_IP_NETWORKS = [
    ipaddress.ip_network(x) for x in [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    ]
]

VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "aes-128-ctr", "aes-192-ctr",
    "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5",
]

_thread_local = threading.local()


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)


def session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        })
        _thread_local.session = s
    return s


def atomic_write(path, data, binary=False):
    tmp = f"{path}.tmp"
    mode = "wb" if binary else "w"
    with open(tmp, mode, encoding=None if binary else "utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def safe_download(url, dest_path):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    tmp = dest_path + ".tmp"
    with urllib.request.urlopen(req, timeout=30) as response, open(tmp, "wb") as f:
        shutil.copyfileobj(response, f)
    os.replace(tmp, dest_path)


def setup_environment():
    print("[*] 准备数据库与 Xray...")
    if not os.path.exists("Country.mmdb"):
        safe_download(
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
            "Country.mmdb",
        )
    if not os.path.exists("ASN.mmdb"):
        safe_download(
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
            "ASN.mmdb",
        )

    if not os.path.exists("xray"):
        safe_download(
            "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip",
            "xray.zip",
        )
        with zipfile.ZipFile("xray.zip") as z:
            z.extract("xray", ".")
        os.chmod("xray", 0o755)
        os.remove("xray.zip")


def b64decode_text(text):
    text = re.sub(r"\s+", "", text or "")
    if not text:
        return ""
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, altchars=b"-_", validate=False).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return ""


def extract_nodes_from_text(text):
    found = set()
    queue = [text or ""]
    seen = set()

    for _ in range(4):
        current = queue.pop(0) if queue else ""
        if not current or current in seen:
            continue
        seen.add(current)

        for node in re.findall(
            r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s"\'<>]+',
            current,
            re.I,
        ):
            found.add(node.rstrip(".,;\"')]}"))

        decoded = b64decode_text(current)
        if decoded and decoded not in seen:
            queue.append(decoded)

        if not queue:
            break

    return found


def fetch_one(url):
    try:
        r = session().get(url, timeout=25)
        if r.ok:
            nodes = extract_nodes_from_text(r.text)
            print(f"[+] {len(nodes):5d}  {url}")
            return nodes
        print(f"[!] HTTP {r.status_code}  {url}")
    except Exception as e:
        print(f"[!] {url} -> {e}")
    return set()


def fetch_raw_nodes():
    print("[*] 抓取节点...")
    nodes = set()
    with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as ex:
        futures = [ex.submit(fetch_one, u) for u in SOURCE_URLS]
        for f in as_completed(futures):
            try:
                nodes.update(f.result())
            except Exception:
                pass
    result = sorted(nodes)
    print(f"[*] 原始节点: {len(result)}")
    return result


def parse_query(query):
    return {k.lower(): v[-1] for k, v in urllib.parse.parse_qs(
        query or "", keep_blank_values=True
    ).items()}


def parse_vless(raw):
    u = urllib.parse.urlsplit(raw)
    if not u.hostname or not u.port or not u.username:
        return None
    p = parse_query(u.query)
    return {
        "raw": raw, "proto": "vless", "server": u.hostname, "port": u.port,
        "uuid": urllib.parse.unquote(u.username),
        "encryption": p.get("encryption", "none"),
        "network": p.get("type", "tcp"),
        "security": p.get("security", "none"),
        "sni": p.get("sni", u.hostname),
        "host": p.get("host", u.hostname),
        "path": urllib.parse.unquote(p.get("path", "/")),
        "flow": p.get("flow", ""),
        "pbk": p.get("pbk", ""),
        "sid": p.get("sid", ""),
        "fp": p.get("fp", "chrome"),
        "service_name": p.get("serviceName", ""),
    }


def parse_vmess(raw):
    data = json.loads(b64decode_text(raw[8:]))
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    uid = str(data.get("id", "")).strip()
    if not server or port <= 0 or not uid:
        return None
    tls = str(data.get("tls", "")).lower() in ("tls", "1", "true")
    return {
        "raw": raw, "proto": "vmess", "server": server, "port": port,
        "uuid": uid, "alter_id": int(data.get("aid", 0) or 0),
        "network": data.get("net", "tcp"),
        "security": "tls" if tls else "none",
        "sni": str(data.get("sni") or data.get("host") or server),
        "host": str(data.get("host") or server),
        "path": urllib.parse.unquote(str(data.get("path") or "/")),
        "cipher": str(data.get("scy") or "auto"),
    }


def parse_trojan(raw):
    u = urllib.parse.urlsplit(raw)
    if not u.hostname or not u.port or u.username is None:
        return None
    p = parse_query(u.query)
    return {
        "raw": raw, "proto": "trojan", "server": u.hostname, "port": u.port,
        "password": urllib.parse.unquote(u.username),
        "network": p.get("type", "tcp"),
        "sni": p.get("sni", u.hostname),
        "host": p.get("host", u.hostname),
        "path": urllib.parse.unquote(p.get("path", "/")),
        "service_name": p.get("serviceName", ""),
    }


def parse_ss(raw):
    u = urllib.parse.urlsplit(raw)
    frag = raw.split("#", 1)[0][5:]
    server = port = cipher = password = None

    try:
        if "@" in frag:
            user, hostpart = frag.rsplit("@", 1)
            decoded = b64decode_text(user)
            user = decoded or urllib.parse.unquote(user)
            if ":" not in user:
                return None
            cipher, password = user.split(":", 1)
            hu = urllib.parse.urlsplit("//" + hostpart)
            server, port = hu.hostname, hu.port
        else:
            decoded = b64decode_text(frag)
            if "@" not in decoded:
                return None
            user, hostpart = decoded.rsplit("@", 1)
            cipher, password = user.split(":", 1)
            hu = urllib.parse.urlsplit("//" + hostpart)
            server, port = hu.hostname, hu.port
    except Exception:
        return None

    if not server or not port or not cipher or cipher not in VALID_SS_CIPHERS:
        return None

    return {
        "raw": raw, "proto": "ss", "server": server, "port": port,
        "cipher": cipher, "password": password,
    }


def parse_hy2(raw):
    u = urllib.parse.urlsplit(raw)
    if not u.hostname or not u.port:
        return None
    password = urllib.parse.unquote(u.username or "")
    p = parse_query(u.query)
    return {
        "raw": raw, "proto": "hysteria2", "server": u.hostname, "port": u.port,
        "password": password, "sni": p.get("sni", u.hostname),
        "insecure": p.get("insecure", "1") in ("1", "true"),
    }


def parse_node(raw):
    try:
        low = raw.lower()
        if low.startswith("vless://"):
            return parse_vless(raw)
        if low.startswith("vmess://"):
            return parse_vmess(raw)
        if low.startswith("trojan://"):
            return parse_trojan(raw)
        if low.startswith("ss://"):
            return parse_ss(raw)
        if low.startswith(("hy2://", "hysteria2://")):
            return parse_hy2(raw)
    except Exception:
        pass
    return None


def xray_outbound(n):
    p = n["proto"]
    if p == "hysteria2":
        return None

    if p == "vless":
        stream = {"network": n["network"], "security": n["security"]}
        if n["security"] == "reality":
            if not n["pbk"]:
                return None
            stream["realitySettings"] = {
                "serverName": n["sni"], "publicKey": n["pbk"],
                "shortId": n["sid"], "fingerprint": n["fp"],
            }
        elif n["security"] == "tls":
            stream["tlsSettings"] = {
                "serverName": n["sni"], "allowInsecure": True
            }
        if n["network"] == "ws":
            stream["wsSettings"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        elif n["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": n["service_name"]}
        user = {"id": n["uuid"], "encryption": n["encryption"]}
        if n["flow"]:
            user["flow"] = n["flow"]
        return {
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": n["server"], "port": n["port"], "users": [user]
            }]},
            "streamSettings": stream,
        }

    if p == "vmess":
        stream = {"network": n["network"], "security": n["security"]}
        if n["security"] == "tls":
            stream["tlsSettings"] = {
                "serverName": n["sni"], "allowInsecure": True
            }
        if n["network"] == "ws":
            stream["wsSettings"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": n["server"], "port": n["port"],
                "users": [{
                    "id": n["uuid"], "alterId": n["alter_id"], "security": "auto"
                }]
            }]},
            "streamSettings": stream,
        }

    if p == "trojan":
        stream = {
            "network": n["network"], "security": "tls",
            "tlsSettings": {"serverName": n["sni"], "allowInsecure": True},
        }
        if n["network"] == "ws":
            stream["wsSettings"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        elif n["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": n["service_name"]}
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": n["server"], "port": n["port"],
                "password": n["password"]
            }]},
            "streamSettings": stream,
        }

    if p == "ss":
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": n["server"], "port": n["port"],
                "method": n["cipher"], "password": n["password"]
            }]},
        }

    return None


def parse_node_to_xray_outbound(node_str):
    n = parse_node(node_str)
    if not n:
        return None, None, None, "unknown"
    return xray_outbound(n), n["server"], n["port"], (
        "ss" if n["proto"] == "ss" else n["proto"]
    )


def to_clash(n, name):
    p = n["proto"]
    base = {
        "name": name, "server": n["server"], "port": n["port"], "udp": True
    }

    if p == "vless":
        base.update({
            "type": "vless", "uuid": n["uuid"],
            "tls": n["security"] in ("tls", "reality"),
            "skip-cert-verify": True,
        })
        if n["flow"]:
            base["flow"] = n["flow"]
        if n["security"] in ("tls", "reality"):
            base["servername"] = n["sni"]
        if n["security"] == "reality":
            base["reality-opts"] = {"public-key": n["pbk"], "short-id": n["sid"]}
            base["client-fingerprint"] = n["fp"]
        if n["network"] == "ws":
            base["network"] = "ws"
            base["ws-opts"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        return base

    if p == "vmess":
        base.update({
            "type": "vmess", "uuid": n["uuid"],
            "alterId": n["alter_id"], "cipher": n["cipher"],
            "tls": n["security"] == "tls", "skip-cert-verify": True,
        })
        if n["security"] == "tls":
            base["servername"] = n["sni"]
        if n["network"] == "ws":
            base["network"] = "ws"
            base["ws-opts"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        return base

    if p == "trojan":
        base.update({
            "type": "trojan", "password": n["password"],
            "sni": n["sni"], "skip-cert-verify": True,
        })
        if n["network"] == "ws":
            base["network"] = "ws"
            base["ws-opts"] = {
                "path": n["path"], "headers": {"Host": n["host"]}
            }
        return base

    if p == "ss":
        base.update({
            "type": "ss", "cipher": n["cipher"],
            "password": n["password"],
        })
        return base

    return None


def convert_to_clash_dict(node_str, name):
    n = parse_node(node_str)
    return to_clash(n, name) if n else None


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_exit_ip(proxies):
    for url in (
        "https://api64.ipify.org",
        "https://api.ipify.org",
        "https://ip.seeip.org",
    ):
        try:
            r = session().get(url, proxies=proxies, timeout=4)
            if r.ok:
                value = r.text.strip()
                try:
                    ipaddress.ip_address(value)
                    if ipaddress.ip_address(value).is_global:
                        return value
                except Exception:
                    pass
        except Exception:
            pass
    return None


def test_single_node_xray(item):
    raw, server, port, proto = item
    n = parse_node(raw)
    outbound = xray_outbound(n) if n else None
    if not outbound or proto == "hysteria2":
        return None

    cfg_path = f"xray_tmp_{uuid.uuid4().hex}.json"
    socks_port = find_free_port()

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }

    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        proc = subprocess.Popen(
            ["./xray", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        ready = False
        for _ in range(20):
            if proc.poll() is not None:
                break
            try:
                r = session().get(
                    "https://www.google.com/generate_204",
                    proxies=proxies,
                    timeout=1.8,
                )
                if r.status_code in (200, 204):
                    ready = True
                    break
            except Exception:
                time.sleep(0.08)

        if not ready:
            return None

        exit_ip = get_exit_ip(proxies)
        if not exit_ip:
            return None

        return (
            raw, server, port, proto, exit_ip,
            int(0), True
        )
    except Exception:
        return None
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            os.remove(cfg_path)
        except Exception:
            pass


def run_real_delay_test_xray(candidates):
    print(f"[*] Xray 测活: {len(candidates)}")
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_TEST_WORKERS) as ex:
        futures = [ex.submit(test_single_node_xray, x) for x in candidates]
        for f in as_completed(futures):
            try:
                result = f.result()
                if result:
                    alive.append(result)
                    if len(alive) % 20 == 0:
                        print(f"[+] 已通过: {len(alive)}")
            except Exception:
                pass

    alive.sort(key=lambda x: (x[4], x[3], x[1], x[2], x[0]))
    print(f"[+] 测活完成: {len(alive)}")
    return alive


def rdns(ip):
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.5)
        try:
            return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return ""


def is_cloudflare(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return any(obj in x for x in CLOUDFLARE_IP_NETWORKS)
    except Exception:
        return False


def strict_residential(ip, asn, org):
    if not ip or is_cloudflare(ip):
        return False

    try:
        asn = int(asn or 0)
    except Exception:
        asn = 0

    if asn in DATACENTER_ASNS:
        return False

    org = str(org or "").lower()
    if any(x in org for x in IDC_KEYWORDS):
        return False

    if not any(x in org for x in RESIDENTIAL_KEYWORDS):
        return False

    ptr = rdns(ip)
    if any(x in ptr for x in (
        "server", "hosting", "vps", "cloud", "datacenter",
        "dedicated", "colocation", "colo",
    )):
        return False

    return True


def classify_and_filter(alive_nodes):
    country_reader = maxminddb.open_database("Country.mmdb")
    asn_reader = maxminddb.open_database("ASN.mmdb")
    result = []

    try:
        for raw, server, port, proto, exit_ip, delay, confirmed in alive_nodes:
            if not confirmed or not exit_ip:
                continue

            country = "OTHER"
            asn = 0
            org = ""

            try:
                c = country_reader.get(exit_ip)
                code = (c or {}).get("country", {}).get("iso_code")
                if code and code.upper() not in ("T1", "A1", "A2", "XX", "ZZ"):
                    country = code.upper()
            except Exception:
                pass

            try:
                a = asn_reader.get(exit_ip)
                asn = (a or {}).get("autonomous_system_number", 0)
                org = (a or {}).get("autonomous_system_organization", "")
            except Exception:
                pass

            proxy = convert_to_clash_dict(raw, "temp")
            if not proxy:
                continue

            result.append({
                "link": raw,
                "clash_proxy": proxy,
                "country": country,
                "is_residential": strict_residential(exit_ip, asn, org),
                "exit_ip": exit_ip,
                "port": port,
                "proto": proto,
                "delay": delay,
                "asn": asn,
                "org": org,
            })
    finally:
        country_reader.close()
        asn_reader.close()

    # 完全相同配置稳定去重
    unique = {}
    for item in result:
        core = item["link"].split("#", 1)[0].strip()
        key = hashlib.sha256(core.encode("utf-8")).hexdigest()
        old = unique.get(key)
        if old is None or item["delay"] < old["delay"]:
            unique[key] = item

    result = list(unique.values())

    # 每个真实家宽出口 IP 只保留一个，优先较快节点
    residential = {}
    for item in result:
        if not item["is_residential"]:
            continue
        ip = item["exit_ip"]
        old = residential.get(ip)
        if old is None or item["delay"] < old["delay"]:
            residential[ip] = item

    residential_ids = {id(x) for x in residential.values()}
    for item in result:
        item["is_residential"] = id(item) in residential_ids

    result.sort(key=lambda x: (
        0 if x["is_residential"] else 1,
        x["country"], x["delay"], x["proto"],
        x["server"], x["port"], x["exit_ip"],
    ))

    print(
        f"[*] 最终节点: {len(result)} | "
        f"严格独立家宽: {len(residential)}"
    )
    return result


def rename_node_link(raw, name):
    try:
        if raw.startswith("vmess://"):
            data = json.loads(b64decode_text(raw[8:]))
            data["ps"] = name
            return "vmess://" + base64.b64encode(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            ).decode()
        return raw.split("#", 1)[0] + "#" + urllib.parse.quote(name, safe="")
    except Exception:
        return raw


def get_country_flag(cc):
    if not cc or cc == "OTHER" or len(cc) != 2:
        return "🌐"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


def format_node_group(nodes):
    links, proxies = [], []
    for idx, item in enumerate(nodes, 1):
        cc = item["country"]
        flag = get_country_flag(cc)
        cname = COUNTRY_NAMES.get(cc, cc)
        tag = " (家宽)" if item["is_residential"] else ""
        name = f"{flag} {cname} {idx:02d}{tag} - xiaohe"

        proxy = dict(item["clash_proxy"])
        proxy["name"] = name
        proxies.append(proxy)
        links.append(rename_node_link(item["link"], name))

    return links, proxies


def export_clash_yaml(proxies, path):
    names = [x["name"] for x in proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {
                "name": "AUTO", "type": "url-test",
                "url": "https://www.google.com/generate_204",
                "interval": 300, "proxies": names,
            },
        ],
        "rules": ["MATCH,PROXIES"],
    }
    atomic_write(path, yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False
    ))


def singbox_outbound(n, tag):
    p = n["proto"]

    if p == "vless":
        o = {
            "type": "vless", "tag": tag, "server": n["server"],
            "server_port": n["port"], "uuid": n["uuid"],
        }
        if n["flow"]:
            o["flow"] = n["flow"]
        if n["security"] in ("tls", "reality"):
            tls = {"enabled": True, "server_name": n["sni"], "insecure": True}
            if n["security"] == "reality":
                tls["reality"] = {
                    "enabled": True, "public_key": n["pbk"], "short_id": n["sid"]
                }
            o["tls"] = tls
        if n["network"] == "ws":
            o["transport"] = {
                "type": "ws", "path": n["path"],
                "headers": {"Host": n["host"]},
            }
        elif n["network"] == "grpc":
            o["transport"] = {
                "type": "grpc", "service_name": n["service_name"]
            }
        return o

    if p == "vmess":
        o = {
            "type": "vmess", "tag": tag, "server": n["server"],
            "server_port": n["port"], "uuid": n["uuid"],
            "security": n["cipher"],
        }
        if n["security"] == "tls":
            o["tls"] = {"enabled": True, "server_name": n["sni"], "insecure": True}
        if n["network"] == "ws":
            o["transport"] = {
                "type": "ws", "path": n["path"],
                "headers": {"Host": n["host"]},
            }
        return o

    if p == "trojan":
        o = {
            "type": "trojan", "tag": tag, "server": n["server"],
            "server_port": n["port"], "password": n["password"],
            "tls": {"enabled": True, "server_name": n["sni"], "insecure": True},
        }
        if n["network"] == "ws":
            o["transport"] = {
                "type": "ws", "path": n["path"],
                "headers": {"Host": n["host"]},
            }
        elif n["network"] == "grpc":
            o["transport"] = {"type": "grpc", "service_name": n["service_name"]}
        return o

    if p == "ss":
        return {
            "type": "shadowsocks", "tag": tag, "server": n["server"],
            "server_port": n["port"], "method": n["cipher"],
            "password": n["password"],
        }

    if p == "hysteria2":
        return {
            "type": "hysteria2", "tag": tag, "server": n["server"],
            "server_port": n["port"], "password": n["password"],
            "tls": {
                "enabled": True, "server_name": n["sni"],
                "insecure": n["insecure"],
            },
        }

    return None


def export_singbox(nodes, path):
    outbounds = []
    names = []

    for item in nodes:
        n = parse_node(item["link"])
        if not n:
            continue
        tag = item["clash_proxy"]["name"]
        o = singbox_outbound(n, tag)
        if o:
            outbounds.append(o)
            names.append(tag)

    config = {
        "log": {"level": "warn"},
        "outbounds": [
            {
                "type": "selector", "tag": "select",
                "outbounds": ["auto"] + names,
            },
            {
                "type": "urltest", "tag": "auto",
                "outbounds": names,
                "url": "https://www.google.com/generate_204",
                "interval": "5m",
            },
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
    }
    atomic_write(path, json.dumps(config, ensure_ascii=False, indent=2))


def write_b64(path, links):
    data = base64.b64encode("\n".join(links).encode()).decode()
    atomic_write(path, data)


def export_subscriptions(nodes):
    ensure_directories()

    residential = [x for x in nodes if x["is_residential"]]
    normal = [x for x in nodes if not x["is_residential"]]

    all_links, all_proxies = format_node_group(nodes)
    write_b64(os.path.join(OUTPUT_DIR, "v2ray.txt"), all_links)
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox(nodes, os.path.join(OUTPUT_DIR, "singbox.json"))

    res_links, res_proxies = format_node_group(residential)
    write_b64(os.path.join(OUTPUT_DIR, "residential.txt"), res_links)

    for name in ("residential-clash.yaml", "residential-singbox.json"):
        p = os.path.join(OUTPUT_DIR, name)
        if os.path.exists(p):
            os.remove(p)

    if res_proxies:
        export_clash_yaml(
            res_proxies,
            os.path.join(OUTPUT_DIR, "residential-clash.yaml"),
        )
        export_singbox(
            residential,
            os.path.join(OUTPUT_DIR, "residential-singbox.json"),
        )

    shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
    shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)

    by_country = {}
    for item in normal:
        by_country.setdefault(item["country"], []).append(item)

    for cc, items in sorted(by_country.items()):
        links, proxies = format_node_group(items)
        write_b64(os.path.join(COUNTRY_DIR, f"{cc}.txt"), links)
        export_clash_yaml(
            proxies, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml")
        )
        export_singbox(
            items, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json")
        )

    by_res_country = {}
    for item in residential:
        by_res_country.setdefault(item["country"], []).append(item)

    for cc, items in sorted(by_res_country.items()):
        links, proxies = format_node_group(items)
        write_b64(
            os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"), links
        )
        export_clash_yaml(
            proxies,
            os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"),
        )
        export_singbox(
            items,
            os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"),
        )

    print(f"[+] 导出完成: 全部 {len(nodes)} | 家宽 {len(residential)}")
    return len(nodes), len(residential)


def output_fingerprint():
    h = hashlib.sha256()
    if not os.path.exists(OUTPUT_DIR):
        return ""
    for root, _, files in os.walk(OUTPUT_DIR):
        for fn in sorted(files):
            path = os.path.join(root, fn)
            h.update(os.path.relpath(path, OUTPUT_DIR).encode())
            with open(path, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:12]


def count_b64(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
        return len([x for x in b64decode_text(text).splitlines() if x.strip()])
    except Exception:
        return 0


def update_readme():
    repo = os.environ.get("GITHUB_REPOSITORY", "hezhanleiok/freesub").strip()
    version = output_fingerprint()

    total = count_b64(os.path.join(OUTPUT_DIR, "v2ray.txt"))
    res = count_b64(os.path.join(OUTPUT_DIR, "residential.txt"))

    cdn = f"https://cdn.jsdelivr.net/gh/{repo}@main/output"
    raw = f"https://raw.githubusercontent.com/{repo}/main/output"

    res_rows = []
    for fn in sorted(os.listdir(RESIDENTIAL_COUNTRY_DIR)):
        if not fn.endswith(".txt"):
            continue
        cc = fn[:-4]
        cnt = count_b64(os.path.join(RESIDENTIAL_COUNTRY_DIR, fn))
        if not cnt:
            continue
        name = COUNTRY_NAMES.get(cc, cc)
        flag = get_country_flag(cc)
        res_rows.append(
            f"| {flag} {name} | {cnt} | "
            f"[V2RayN]({cdn}/residential-by-country/{cc}.txt?v={version}) | "
            f"[Clash]({cdn}/residential-by-country/clash-{cc}.yaml?v={version}) | "
            f"[sing-box]({cdn}/residential-by-country/singbox-{cc}.json?v={version}) |"
        )

    normal_rows = []
    for fn in sorted(os.listdir(COUNTRY_DIR)):
        if not fn.endswith(".txt"):
            continue
        cc = fn[:-4]
        cnt = count_b64(os.path.join(COUNTRY_DIR, fn))
        if not cnt:
            continue
        name = COUNTRY_NAMES.get(cc, cc)
        flag = get_country_flag(cc)
        normal_rows.append(
            f"| {flag} {name} | {cnt} | "
            f"[V2RayN]({cdn}/by-country/{cc}.txt?v={version}) | "
            f"[Clash]({cdn}/by-country/clash-{cc}.yaml?v={version}) | "
            f"[sing-box]({cdn}/by-country/singbox-{cc}.json?v={version}) |"
        )

    readme = f"""# 🚀 免费节点自动测活订阅池

> Xray 实际代理测试 + 真实出口 IP 检测 + ASN/ISP/rDNS 严格家宽筛选。

## 全部节点

| 类型 | 数量 | CDN | Raw |
|---|---:|---|---|
| Clash | {total} | [订阅]({cdn}/clash.yaml?v={version}) | [Raw]({raw}/clash.yaml) |
| V2RayN | {total} | [订阅]({cdn}/v2ray.txt?v={version}) | [Raw]({raw}/v2ray.txt) |
| sing-box | {total} | [订阅]({cdn}/singbox.json?v={version}) | [Raw]({raw}/singbox.json) |

## 🏠 严格家宽

> 必须确认真实出口 IP，并排除 Cloudflare、IDC ASN、云厂商/托管关键词及明显机房 rDNS。

**当前独立家宽出口：{res}**

| 地区 | 数量 | V2RayN | Clash | sing-box |
|---|---:|---|---|---|
{chr(10).join(res_rows) if res_rows else "| 暂无 | 0 | - | - | - |"}

## 🗺️ 普通节点

| 地区 | 数量 | V2RayN | Clash | sing-box |
|---|---:|---|---|---|
{chr(10).join(normal_rows) if normal_rows else "| 暂无 | 0 | - | - | - |"}

## ⚙️ 更新

GitHub Actions 每 6 小时自动抓取、实测、筛选和发布。
"""
    atomic_write("README.md", readme)
    print(f"[+] README 更新: 全部 {total} / 家宽 {res}")


def previous_count():
    return count_b64(os.path.join(OUTPUT_DIR, "v2ray.txt"))


def main():
    ensure_directories()
    setup_environment()

    raw_nodes = fetch_raw_nodes()
    candidates = []

    for raw in raw_nodes:
        n = parse_node(raw)
        if not n or n["port"] <= 0 or not n["server"]:
            continue
        if n["proto"] == "hysteria2":
            continue
        if xray_outbound(n):
            candidates.append((raw, n["server"], n["port"], n["proto"]))

    # 稳定去重
    seen = set()
    candidates = [
        x for x in candidates
        if not (hashlib.sha256(x[0].split("#", 1)[0].encode()).hexdigest() in seen
                or seen.add(hashlib.sha256(x[0].split("#", 1)[0].encode()).hexdigest()))
    ]

    print(f"[*] 合规候选: {len(candidates)}")

    alive = run_real_delay_test_xray(candidates)
    verified = classify_and_filter(alive)

    old = previous_count()
    if old >= MIN_PUBLISH_NODES and len(verified) < MIN_PUBLISH_NODES:
        print(f"[!] 本次仅得到 {len(verified)} 个节点，保留上次结果")
        return

    if old >= 20 and len(verified) < max(MIN_PUBLISH_NODES, old // 5):
        print(f"[!] 节点数量异常下降: {old} -> {len(verified)}，保留上次结果")
        return

    export_subscriptions(verified)
    update_readme()


if __name__ == "__main__":
    main()
