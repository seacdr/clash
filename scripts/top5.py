#!/usr/bin/env python3

import base64
import concurrent.futures
import hashlib
import html
import ipaddress
import os
import re
import socket
import time
from urllib.parse import unquote, urlparse

import requests


# ============================================================
# Configuration
# ============================================================

OUTPUT_FILE = "output/top5.txt"

TOP_N = 10

# TCP connection timeout
CONNECT_TIMEOUT = 2.5

# Number of workers used for testing
MAX_WORKERS = 80

# Only keep nodes whose TCP connection succeeds
MIN_LATENCY = 1
MAX_LATENCY = 3000


SOURCES = {
    # --------------------------------------------------------
    # Pawdroid
    # --------------------------------------------------------
    "pawdroid": [
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    ],

    # --------------------------------------------------------
    # free-nodes / v2rayfree
    # --------------------------------------------------------
    "v2rayfree": [
        "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/README.md",
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
    "tuic://",
)


def detect_protocol(line: str):
    line = line.strip()

    lower = line.lower()

    for protocol in PROTOCOL_PREFIXES:
        if lower.startswith(protocol):
            return protocol[:-3]

    return None


# ============================================================
# Extract proxy URLs from arbitrary text
# ============================================================

URL_PATTERN = re.compile(
    r"(?:ssr|ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s\"'<>]+",
    re.IGNORECASE,
)


def extract_urls(text: str):
    """
    Extract proxy URLs from:
      - Base64 subscriptions
      - normal text
      - markdown
      - YAML-ish text
    """

    results = set()

    # First: direct URL extraction
    for match in URL_PATTERN.findall(text):
        results.add(html.unescape(match).rstrip("),]"))

    # Second: try Base64 decoding
    cleaned = re.sub(r"\s+", "", text)

    # Only attempt if the content looks like Base64
    if len(cleaned) >= 40 and re.fullmatch(
        r"[A-Za-z0-9+/=_-]+", cleaned
    ):
        try:
            padded = cleaned + "=" * (-len(cleaned) % 4)

            decoded = base64.urlsafe_b64decode(
                padded.encode()
            ).decode(
                "utf-8",
                errors="ignore",
            )

            for match in URL_PATTERN.findall(decoded):
                results.add(
                    html.unescape(match).rstrip("),]")
                )

        except Exception:
            pass

    return results


# ============================================================
# Parse host / port
# ============================================================

def parse_host_port(proxy_url: str):
    protocol = detect_protocol(proxy_url)

    if not protocol:
        return None, None

    try:
        if protocol == "vmess":
            # VMess is Base64 encoded JSON
            payload = proxy_url[len("vmess://"):]

            padded = payload + "=" * (-len(payload) % 4)

            raw = base64.urlsafe_b64decode(
                padded
            ).decode(
                "utf-8",
                errors="ignore",
            )

            # Simple JSON-like extraction.
            host_match = re.search(
                r'"add"\s*:\s*"([^"]+)"',
                raw,
            )

            port_match = re.search(
                r'"port"\s*:\s*"?(\d+)"?',
                raw,
            )

            if not host_match or not port_match:
                return None, None

            return (
                host_match.group(1),
                int(port_match.group(1)),
            )

        # ----------------------------------------------------
        # VLESS / Trojan / Hysteria / TUIC
        # ----------------------------------------------------
        if protocol in (
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "tuic",
        ):
            parsed = urlparse(proxy_url)

            host = parsed.hostname
            port = parsed.port

            return host, port

        # ----------------------------------------------------
        # Shadowsocks
        # ----------------------------------------------------
        if protocol == "ss":
            payload = proxy_url[len("ss://"):]

            # Remove fragment
            payload = payload.split("#", 1)[0]

            # Modern SS format:
            #
            # ss://BASE64(method:password)@host:port
            #
            if "@" in payload:
                encoded, server = payload.rsplit("@", 1)

                try:
                    padded = encoded + "=" * (
                        -len(encoded) % 4
                    )

                    decoded = base64.urlsafe_b64decode(
                        padded
                    ).decode(
                        "utf-8",
                        errors="ignore",
                    )

                    # decoded should be method:password
                    if ":" in decoded:
                        parsed_server = urlparse(
                            "ss://" + server
                        )

                        return (
                            parsed_server.hostname,
                            parsed_server.port,
                        )

                except Exception:
                    pass

            # Legacy format:
            #
            # ss://BASE64(method:password@host:port)
            #
            try:
                padded = payload + "=" * (
                    -len(payload) % 4
                )

                decoded = base64.urlsafe_b64decode(
                    padded
                ).decode(
                    "utf-8",
                    errors="ignore",
                )

                parsed = urlparse(
                    "ss://" + decoded
                )

                return (
                    parsed.hostname,
                    parsed.port,
                )

            except Exception:
                return None, None

        # ----------------------------------------------------
        # SSR
        # ----------------------------------------------------
        if protocol == "ssr":
            payload = proxy_url[len("ssr://"):]

            padded = payload + "=" * (
                -len(payload) % 4
            )

            decoded = base64.urlsafe_b64decode(
                padded
            ).decode(
                "utf-8",
                errors="ignore",
            )

            # SSR:
            #
            # host:port:protocol:method:obfs:
            # password_base64/?params
            #
            parts = decoded.split(":", 5)

            if len(parts) >= 2:
                host = parts[0]

                try:
                    port = int(parts[1])
                except ValueError:
                    return None, None

                return host, port

    except Exception:
        return None, None

    return None, None


# ============================================================
# DNS / IP validation
# ============================================================

def valid_host(host):
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

    # Domain name
    if re.fullmatch(
        r"[A-Za-z0-9._-]+",
        host,
    ):
        return True

    return False


# ============================================================
# TCP benchmark
# ============================================================

def tcp_latency(host, port):
    """
    Measure TCP connect latency.

    This is intentionally protocol-independent.

    It works for:
      SS
      SSR
      VMess
      VLESS
      Trojan
      Hysteria
      TUIC
    """

    if not valid_host(host):
        return None

    try:
        start = time.perf_counter()

        with socket.create_connection(
            (host, port),
            timeout=CONNECT_TIMEOUT,
        ):
            pass

        elapsed = (
            time.perf_counter() - start
        ) * 1000

        if (
            elapsed < MIN_LATENCY
            or elapsed > MAX_LATENCY
        ):
            return None

        return round(elapsed, 1)

    except Exception:
        return None


# ============================================================
# Download sources
# ============================================================

def download_source(url):
    print(f"[DOWNLOAD] {url}")

    try:
        response = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent":
                    "Mozilla/5.0 "
                    "Top5-Node-Collector/1.0"
            },
        )

        response.raise_for_status()

        return response.text

    except Exception as exc:
        print(
            f"[ERROR] download failed: "
            f"{url}: {exc}"
        )

        return ""


# ============================================================
# Collect all nodes
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

            for node in nodes:

                protocol = detect_protocol(node)

                if not protocol:
                    continue

                host, port = parse_host_port(node)

                if not host or not port:
                    continue

                key = hashlib.sha256(
                    node.encode("utf-8")
                ).hexdigest()

                if key not in all_nodes:
                    all_nodes[key] = {
                        "url": node,
                        "protocol": protocol,
                        "host": host,
                        "port": port,
                        "source": source_name,
                    }

    return list(all_nodes.values())


# ============================================================
# Benchmark all nodes
# ============================================================

def benchmark(nodes):

    print(
        f"[TEST] Testing {len(nodes)} nodes..."
    )

    def test(node):

        latency = tcp_latency(
            node["host"],
            node["port"],
        )

        if latency is None:
            return None

        node["latency"] = latency

        return node

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(test, node)
            for node in nodes
        ]

        for future in concurrent.futures.as_completed(
            futures
        ):

            result = future.result()

            if result:
                results.append(result)

    return results


# ============================================================
# Select Top5 for every protocol
# ============================================================

def select_top5(nodes):

    grouped = {}

    for node in nodes:

        protocol = node["protocol"]

        grouped.setdefault(
            protocol,
            [],
        ).append(node)

    selected = {}

    for protocol, items in grouped.items():

        items.sort(
            key=lambda x: x["latency"]
        )

        selected[protocol] = items[:TOP_N]

    return selected


# ============================================================
# Generate subscription file
# ============================================================

def write_output(selected):

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True,
    )

    now = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC",
        time.gmtime(),
    )

    lines = []

    lines.append(
        "# Auto-generated by GitHub Actions"
    )

    lines.append(
        f"# Updated: {now}"
    )

    lines.append(
        "# Top 5 nodes per protocol"
    )

    lines.append(
        "# Benchmark: TCP connect latency"
    )

    lines.append("")

    protocol_order = [
        "ss",
        "ssr",
        "vmess",
        "vless",
        "trojan",
        "hysteria",
        "hysteria2",
        "tuic",
    ]

    for protocol in protocol_order:

        nodes = selected.get(
            protocol,
            [],
        )

        if not nodes:
            continue

        lines.append(
            f"# =============================="
        )

        lines.append(
            f"# {protocol.upper()} Top {len(nodes)}"
        )

        lines.append(
            f"# =============================="
        )

        for index, node in enumerate(
            nodes,
            start=1,
        ):

            lines.append(
                "# "
                f"{index}. "
                f"{node['latency']} ms | "
                f"{node['host']}:{node['port']} | "
                f"source={node['source']}"
            )

            lines.append(
                node["url"]
            )

        lines.append("")

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            "\n".join(lines)
        )

    print(
        f"[OUTPUT] {OUTPUT_FILE}"
    )


# ============================================================
# Main
# ============================================================

def main():

    print(
        "======================================"
    )

    print(
        "        TOP5 NODE COLLECTOR"
    )

    print(
        "======================================"
    )

    nodes = collect_nodes()

    print(
        f"[COLLECT] Total unique nodes: "
        f"{len(nodes)}"
    )

    if not nodes:
        raise RuntimeError(
            "No proxy nodes were collected."
        )

    working = benchmark(nodes)

    print(
        f"[TEST] Working nodes: "
        f"{len(working)}"
    )

    if not working:
        raise RuntimeError(
            "No working nodes found."
        )

    selected = select_top5(
        working
    )

    print("")
    print(
        "========== SELECTED =========="
    )

    for protocol, nodes in selected.items():

        print(
            f"{protocol.upper()}: "
            f"{len(nodes)}"
        )

        for node in nodes:

            print(
                f"  {node['latency']:7.1f} ms "
                f"{node['host']}:{node['port']}"
            )

    print(
        "=============================="
    )

    write_output(selected)


if __name__ == "__main__":
    main()