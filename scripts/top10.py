#!/usr/bin/env python3
"""
Collect public proxy nodes, test TCP latency, then benchmark real download
through the node with sing-box.

Ranking:
    latency 30%
    download speed 70%

Important:
- TCP connect latency is only the first-stage filter.
- Download speed is measured through the actual proxy protocol when sing-box
  can parse the node.
- SSR is kept for latency testing but is not speed-tested by sing-box.
- Results are highly dependent on the GitHub Actions runner region/ISP.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests


# ============================================================
# Configuration
# ============================================================

OUTPUT_FILE = "output/top10.txt"
TOP_N = 10

# TCP latency
CONNECT_TIMEOUT = 2.5
MAX_WORKERS = 80
MIN_LATENCY = 1
MAX_LATENCY = 3000

# Speed benchmark
SING_BOX = os.getenv("SING_BOX", "sing-box")
SPEED_CANDIDATES = int(os.getenv("SPEED_CANDIDATES", "30"))
SPEED_WORKERS = int(os.getenv("SPEED_WORKERS", "8"))
SPEED_TIMEOUT = int(os.getenv("SPEED_TIMEOUT", "15"))
SPEED_SECONDS = int(os.getenv("SPEED_SECONDS", "8"))
SPEED_URL = os.getenv(
    "SPEED_URL",
    "https://speed.cloudflare.com/__down?bytes=25000000",
)

LATENCY_WEIGHT = 0.30
SPEED_WEIGHT = 0.70

# Local HTTP proxy port range used by sing-box.
LOCAL_PORT_MIN = 18080
LOCAL_PORT_MAX = 18999

USER_AGENT = "Mozilla/5.0 Top10-Node-Collector/2.0"


# ============================================================
# Public sources
# Selected for popularity/activity and direct node feeds.
# Stars are informational; source priority does not override
# measured node performance.
# ============================================================

SOURCES = {
    # Existing source; frequently refreshed.
    "pawdroid": [
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    ],

    # 13k+ stars at the time of research.
    "v2rayfree": [
        "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/README.md",
    ],

    # ~2k stars; publishes a v2ray subscription feed.
    "proxypool": [
        "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    ],

    # ~6k stars; repository README also exposes current nodes.
    "clash-freenode": [
        "https://raw.githubusercontent.com/OpenRunner/clash-freenode/main/README.md",
    ],

    # Large, frequently updated public lists. Keep protocol feeds separate
    # so one huge HTTP/SOCKS list does not dominate collection time.
    "getfreeproxy": [
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/tuic.txt",
    ],
}


# ============================================================
# Protocol detection
# ============================================================

PROTOCOL_PREFIXES = (
    "ss://",
    "ssr://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy://",
    "hy2://",
    "tuic://",
)


def detect_protocol(line: str) -> str | None:
    line = line.strip().lower()

    for protocol in PROTOCOL_PREFIXES:
        if line.startswith(protocol):
            if protocol == "hy://":
                return "hysteria"
            if protocol == "hy2://":
                return "hysteria2"
            return protocol[:-3]

    return None


# ============================================================
# Extract proxy URLs
# ============================================================

URL_PATTERN = re.compile(
    r"(?:ssr|ss|vmess|vless|trojan|hysteria2|hysteria|hy2|hy|tuic)://[^\s\"'<>]+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> set[str]:
    results: set[str] = set()

    # Direct URLs / Markdown / YAML-ish content.
    for match in URL_PATTERN.findall(text):
        results.add(html.unescape(match).rstrip("),]}"))

    # Base64 subscriptions.
    cleaned = re.sub(r"\s+", "", text)

    if len(cleaned) >= 40 and re.fullmatch(
        r"[A-Za-z0-9+/=_-]+", cleaned
    ):
        try:
            padded = cleaned + "=" * (-len(cleaned) % 4)
            decoded = base64.urlsafe_b64decode(
                padded.encode()
            ).decode("utf-8", errors="ignore")

            for match in URL_PATTERN.findall(decoded):
                results.add(html.unescape(match).rstrip("),]}"))
        except Exception:
            pass

    return results


# ============================================================
# Parsing helpers
# ============================================================

def b64decode_text(value: str) -> str:
    value = value.strip()
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode()).decode(
        "utf-8", errors="ignore"
    )


def parse_query(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    result = {}
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if values:
            result[key.lower()] = unquote(values[-1])
    return result


def truthy(value: str | None) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def valid_host(host: str | None) -> bool:
    if not host:
        return False

    host = host.strip()

    if len(host) > 253:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return bool(re.fullmatch(r"[A-Za-z0-9._:-]+", host))


def parse_host_port(proxy_url: str):
    protocol = detect_protocol(proxy_url)

    if not protocol:
        return None, None

    try:
        if protocol == "vmess":
            payload = proxy_url[len("vmess://"):]
            raw = b64decode_text(payload)
            obj = json.loads(raw)

            host = obj.get("add")
            port = int(obj.get("port"))

            return host, port

        parsed = urlparse(proxy_url)
        host = parsed.hostname
        port = parsed.port

        return host, port

    except Exception:
        return None, None


# ============================================================
# TCP latency
# ============================================================

def tcp_latency(host: str, port: int):
    if not valid_host(host):
        return None

    try:
        start = time.perf_counter()

        with socket.create_connection(
            (host, port),
            timeout=CONNECT_TIMEOUT,
        ):
            pass

        elapsed = (time.perf_counter() - start) * 1000

        if elapsed < MIN_LATENCY or elapsed > MAX_LATENCY:
            return None

        return round(elapsed, 1)

    except Exception:
        return None


# ============================================================
# Download source
# ============================================================

def download_source(url: str) -> str:
    print(f"[DOWNLOAD] {url}")

    try:
        response = requests.get(
            url,
            timeout=20,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        return response.text

    except Exception as exc:
        print(f"[ERROR] source failed: {url}: {exc}")
        return ""


# ============================================================
# Collect / deduplicate
# ============================================================

def collect_nodes():
    all_nodes = {}

    for source_name, urls in SOURCES.items():
        for url in urls:
            text = download_source(url)

            if not text:
                continue

            nodes = extract_urls(text)

            print(
                f"[SOURCE] {source_name}: "
                f"{len(nodes)} nodes"
            )

            for node_url in nodes:
                protocol = detect_protocol(node_url)

                if not protocol:
                    continue

                host, port = parse_host_port(node_url)

                if not host or not port:
                    continue

                key = hashlib.sha256(
                    node_url.encode("utf-8")
                ).hexdigest()

                if key not in all_nodes:
                    all_nodes[key] = {
                        "url": node_url,
                        "protocol": protocol,
                        "host": host,
                        "port": port,
                        "source": source_name,
                    }

    return list(all_nodes.values())


# ============================================================
# Latency benchmark
# ============================================================

def benchmark_latency(nodes):
    print(f"[LATENCY] Testing {len(nodes)} nodes...")

    def test(node):
        latency = tcp_latency(node["host"], node["port"])

        if latency is None:
            return None

        result = dict(node)
        result["latency"] = latency
        return result

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:
        futures = [executor.submit(test, node) for node in nodes]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()

            if result:
                results.append(result)

    return results


# ============================================================
# URI -> sing-box outbound
# ============================================================

def tls_from_query(q: dict[str, str]) -> dict:
    security = q.get("security", "").lower()

    if security not in {"tls", "reality"}:
        return {}

    tls = {
        "enabled": True,
    }

    sni = q.get("sni") or q.get("server_name")
    if sni:
        tls["server_name"] = sni

    if truthy(q.get("insecure")) or truthy(q.get("allowinsecure")):
        tls["insecure"] = True

    alpn = q.get("alpn")
    if alpn:
        tls["alpn"] = [x for x in alpn.split(",") if x]

    fp = q.get("fp")
    if fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    if security == "reality":
        pbk = q.get("pbk")
        if pbk:
            tls["reality"] = {
                "enabled": True,
                "public_key": pbk,
            }

            sid = q.get("sid")
            if sid:
                tls["reality"]["short_id"] = sid

    return tls


def transport_from_query(q: dict[str, str]) -> dict:
    network = (q.get("type") or q.get("network") or "tcp").lower()

    if network in {"tcp", "raw"}:
        return {}

    if network == "ws":
        transport = {
            "type": "ws",
        }

        path = q.get("path")
        if path:
            transport["path"] = path

        host = q.get("host")
        if host:
            transport["headers"] = {"Host": host}

        return transport

    if network == "grpc":
        transport = {
            "type": "grpc",
        }

        service_name = q.get("servicename") or q.get("serviceName")
        if service_name:
            transport["service_name"] = service_name

        return transport

    if network in {"http", "h2"}:
        transport = {
            "type": "http",
        }

        path = q.get("path")
        if path:
            transport["path"] = path

        host = q.get("host")
        if host:
            transport["headers"] = {"Host": host}

        return transport

    if network == "httpupgrade":
        transport = {
            "type": "httpupgrade",
        }

        path = q.get("path")
        if path:
            transport["path"] = path

        host = q.get("host")
        if host:
            transport["host"] = host

        return transport

    return {}


def vmess_outbound(proxy_url: str):
    try:
        obj = json.loads(
            b64decode_text(proxy_url[len("vmess://"):])
        )

        host = obj.get("add")
        port = int(obj.get("port"))
        uuid = obj.get("id")

        if not host or not uuid:
            return None

        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "security": obj.get("scy") or "auto",
        }

        if obj.get("aid") is not None:
            try:
                outbound["alter_id"] = int(obj["aid"])
            except Exception:
                pass

        tls = str(obj.get("tls") or "").lower()
        if tls:
            q = {
                "security": "tls",
                "sni": obj.get("sni") or obj.get("host") or host,
                "insecure": "1" if truthy(str(obj.get("skip-cert-verify"))) else "0",
                "fp": obj.get("fp") or "",
            }
            outbound["tls"] = tls_from_query(q)

        network = obj.get("net") or "tcp"
        q = {
            "type": network,
            "path": obj.get("path") or "",
            "host": obj.get("host") or "",
            "servicename": obj.get("path") or "",
        }

        transport = transport_from_query(q)
        if transport:
            outbound["transport"] = transport

        return outbound

    except Exception:
        return None


def uri_to_outbound(proxy_url: str):
    protocol = detect_protocol(proxy_url)

    if protocol == "vmess":
        return vmess_outbound(proxy_url)

    try:
        parsed = urlparse(proxy_url)
        q = parse_query(proxy_url)

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None

        # VLESS
        if protocol == "vless":
            uuid = unquote(parsed.username or "")
            if not uuid:
                return None

            outbound = {
                "type": "vless",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "network": q.get("type", "tcp"),
            }

            if q.get("flow"):
                outbound["flow"] = q["flow"]

            tls = tls_from_query(q)
            if tls:
                outbound["tls"] = tls

            transport = transport_from_query(q)
            if transport:
                outbound["transport"] = transport

            if q.get("packetenconding") or q.get("packetencoding"):
                outbound["packet_encoding"] = (
                    q.get("packetenconding")
                    or q.get("packetencoding")
                )

            return outbound

        # Trojan
        if protocol == "trojan":
            password = unquote(parsed.username or "")
            if not password:
                return None

            outbound = {
                "type": "trojan",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "password": password,
            }

            tls = tls_from_query(q)
            if tls:
                outbound["tls"] = tls

            transport = transport_from_query(q)
            if transport:
                outbound["transport"] = transport

            return outbound

        # Shadowsocks
        if protocol == "ss":
            payload = proxy_url[len("ss://"):].split("#", 1)[0]

            if "@" in payload:
                encoded, server = payload.rsplit("@", 1)
                decoded = b64decode_text(encoded)
                if ":" not in decoded:
                    return None
                method, password = decoded.split(":", 1)
                parsed_server = urlparse("ss://" + server)
                host = parsed_server.hostname
                port = parsed_server.port
            else:
                decoded = b64decode_text(payload)
                parsed_server = urlparse("ss://" + decoded)
                userinfo = parsed_server.username or ""
                password = parsed_server.password or ""
                if ":" not in userinfo:
                    return None
                method, password = userinfo.split(":", 1)
                host = parsed_server.hostname
                port = parsed_server.port

            if not host or not port or not method:
                return None

            outbound = {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "method": unquote(method),
                "password": unquote(password),
                "network": "tcp",
            }

            return outbound

        # Hysteria2
        if protocol == "hysteria2":
            password = unquote(parsed.username or "")
            if not password:
                password = unquote(parsed.password or "")

            if not password:
                return None

            outbound = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "password": password,
                "network": "tcp",
            }

            if q.get("obfs") and q.get("obfs-password"):
                outbound["obfs"] = {
                    "type": q["obfs"],
                    "password": q["obfs-password"],
                }

            tls = tls_from_query(q)
            if tls:
                outbound["tls"] = tls

            return outbound

        # TUIC
        if protocol == "tuic":
            uuid = unquote(parsed.username or "")
            password = unquote(parsed.password or "")

            if not uuid or not password:
                return None

            outbound = {
                "type": "tuic",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "password": password,
                "network": "tcp",
            }

            if q.get("congestion-control"):
                outbound["congestion_control"] = q["congestion-control"]

            tls = tls_from_query(q)
            if tls:
                outbound["tls"] = tls

            return outbound

        # Hysteria v1
        if protocol == "hysteria":
            password = unquote(parsed.username or "")
            if not password:
                return None

            outbound = {
                "type": "hysteria",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "password": password,
                "network": "tcp",
            }

            tls = tls_from_query(q)
            if tls:
                outbound["tls"] = tls

            return outbound

    except Exception:
        return None

    return None


# ============================================================
# sing-box process / download benchmark
# ============================================================

def allocate_port() -> int:
    for port in range(LOCAL_PORT_MIN, LOCAL_PORT_MAX):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue

    raise RuntimeError("No free local port available.")


def wait_port(port: int, timeout: float = 4.0) -> bool:
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.2,
            ):
                return True
        except OSError:
            time.sleep(0.05)

    return False


def measure_download_speed(node) -> float | None:
    outbound = uri_to_outbound(node["url"])

    if not outbound:
        return None

    if not shutil.which(SING_BOX):
        return None

    local_port = allocate_port()

    config = {
        "log": {
            "level": "error",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": local_port,
            }
        ],
        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct",
            },
        ],
        "route": {
            "final": "proxy",
        },
    }

    process = None

    with tempfile.TemporaryDirectory(prefix="node-speed-") as tmp:
        config_path = Path(tmp) / "config.json"
        config_path.write_text(
            json.dumps(config, ensure_ascii=False),
            encoding="utf-8",
        )

        try:
            # Validate config before starting.
            check = subprocess.run(
                [SING_BOX, "check", "-c", str(config_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if check.returncode != 0:
                return None

            process = subprocess.Popen(
                [SING_BOX, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            if not wait_port(local_port):
                return None

            proxies = {
                "http": f"http://127.0.0.1:{local_port}",
                "https": f"http://127.0.0.1:{local_port}",
            }

            start = time.perf_counter()
            total = 0

            with requests.get(
                SPEED_URL,
                proxies=proxies,
                stream=True,
                timeout=SPEED_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            ) as response:
                response.raise_for_status()

                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue

                    total += len(chunk)
                    elapsed = time.perf_counter() - start

                    if elapsed >= SPEED_SECONDS:
                        break

            elapsed = max(time.perf_counter() - start, 0.001)

            if total < 128 * 1024:
                return None

            # Mbit/s
            return round(total * 8 / elapsed / 1_000_000, 2)

        except Exception:
            return None

        finally:
            if process is not None:
                try:
                    process.terminate()
                    process.wait(timeout=1.5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass


def benchmark_speed(nodes):
    print(
        f"[SPEED] Benchmarking up to "
        f"{SPEED_CANDIDATES} candidates per protocol..."
    )

    grouped = {}

    for node in nodes:
        grouped.setdefault(node["protocol"], []).append(node)

    candidates = []

    for protocol, items in grouped.items():
        items.sort(key=lambda x: x["latency"])
        candidates.extend(items[:SPEED_CANDIDATES])

    print(f"[SPEED] Total candidates: {len(candidates)}")

    def test(node):
        speed = measure_download_speed(node)

        result = dict(node)
        result["speed_mbps"] = speed if speed is not None else 0.0
        result["speed_tested"] = speed is not None
        return result

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=SPEED_WORKERS
    ) as executor:
        futures = [executor.submit(test, node) for node in candidates]

        for index, future in enumerate(
            concurrent.futures.as_completed(futures),
            start=1,
        ):
            result = future.result()
            results.append(result)

            speed = result["speed_mbps"]
            print(
                f"[SPEED] {index}/{len(futures)} "
                f"{result['protocol']:10s} "
                f"{result['latency']:7.1f} ms "
                f"{speed:8.2f} Mbps "
                f"{result['host']}:{result['port']}"
            )

    return results


# ============================================================
# Weighted ranking
# ============================================================

def percentile(values, p):
    if not values:
        return 0.0

    values = sorted(values)

    if len(values) == 1:
        return float(values[0])

    index = (len(values) - 1) * p
    low = int(index)
    high = min(low + 1, len(values) - 1)
    fraction = index - low

    return values[low] * (1 - fraction) + values[high] * fraction


def normalize_lower_better(value, low, high):
    if high <= low:
        return 100.0

    value = min(max(value, low), high)
    return 100.0 * (high - value) / (high - low)


def normalize_higher_better(value, low, high):
    if high <= low:
        return 100.0 if value > 0 else 0.0

    value = min(max(value, low), high)
    return 100.0 * (value - low) / (high - low)


def rank_nodes(nodes):
    if not nodes:
        return []

    latency_values = [float(x["latency"]) for x in nodes]
    speed_values = [
        float(x["speed_mbps"])
        for x in nodes
        if x.get("speed_tested")
    ]

    # Percentile clipping prevents one extreme node from destroying
    # the scale of the weighted score.
    latency_low = percentile(latency_values, 0.05)
    latency_high = percentile(latency_values, 0.95)

    speed_low = percentile(speed_values, 0.05) if speed_values else 0.0
    speed_high = percentile(speed_values, 0.95) if speed_values else 1.0

    ranked = []

    for node in nodes:
        latency_score = normalize_lower_better(
            float(node["latency"]),
            latency_low,
            latency_high,
        )

        if node.get("speed_tested"):
            speed_score = normalize_higher_better(
                float(node["speed_mbps"]),
                speed_low,
                speed_high,
            )
        else:
            # Untested nodes are deliberately penalized because the
            # requested ranking is 70% download speed.
            speed_score = 0.0

        score = (
            LATENCY_WEIGHT * latency_score
            + SPEED_WEIGHT * speed_score
        )

        result = dict(node)
        result["latency_score"] = round(latency_score, 2)
        result["speed_score"] = round(speed_score, 2)
        result["score"] = round(score, 2)

        ranked.append(result)

    ranked.sort(
        key=lambda x: (
            x["score"],
            x["speed_mbps"],
            -x["latency"],
        ),
        reverse=True,
    )

    return ranked


# ============================================================
# Output
# ============================================================

def write_output(ranked):
    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True,
    )

    now = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC",
        time.gmtime(),
    )

    selected = ranked[:TOP_N]

    lines = [
        "# Auto-generated by GitHub Actions",
        f"# Updated: {now}",
        "# Ranking: latency 30% + download speed 70%",
        f"# Speed test URL: {SPEED_URL}",
        "",
        "# ================================================",
        f"# TOP {len(selected)} OVERALL",
        "# ================================================",
        "",
    ]

    for index, node in enumerate(selected, start=1):
        speed = node["speed_mbps"]
        lines.append(
            f"# {index:02d} | score={node['score']:6.2f} | "
            f"latency={node['latency']:7.1f} ms | "
            f"speed={speed:8.2f} Mbps | "
            f"lat_score={node['latency_score']:6.2f} | "
            f"speed_score={node['speed_score']:6.2f} | "
            f"{node['protocol']} | source={node['source']} | "
            f"{node['host']}:{node['port']}"
        )
        lines.append(node["url"])
        lines.append("")

    Path(OUTPUT_FILE).write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print(f"[OUTPUT] {OUTPUT_FILE}")


# ============================================================
# Main
# ============================================================

def main():
    print("==============================================")
    print("       TOP10 NODE COLLECTOR / BENCHMARK")
    print("       Latency 30% + Speed 70%")
    print("==============================================")

    if not shutil.which(SING_BOX):
        print(
            "[WARN] sing-box not found. "
            "Download-speed tests will be unavailable."
        )

    nodes = collect_nodes()

    print(f"[COLLECT] Unique nodes: {len(nodes)}")

    if not nodes:
        raise RuntimeError("No proxy nodes were collected.")

    working = benchmark_latency(nodes)

    print(f"[LATENCY] Working nodes: {len(working)}")

    if not working:
        raise RuntimeError("No working nodes found.")

    # Speed-test only the best latency candidates first.
    speed_results = benchmark_speed(working)

    # Nodes not selected for speed testing are intentionally not part of
    # the final ranking because the requested metric is 70% download speed.
    ranked = rank_nodes(speed_results)

    print("")
    print("=============== TOP 10 ===============")

    for index, node in enumerate(ranked[:TOP_N], start=1):
        print(
            f"{index:02d}. "
            f"score={node['score']:6.2f}  "
            f"lat={node['latency']:7.1f} ms  "
            f"speed={node['speed_mbps']:8.2f} Mbps  "
            f"{node['protocol']:10s}  "
            f"{node['host']}:{node['port']}"
        )

    print("=======================================")

    write_output(ranked)


if __name__ == "__main__":
    main()
