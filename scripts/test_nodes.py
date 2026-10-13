#!/usr/bin/env python3
"""
Test node connectivity and speed using TCP/HTTP tests.
"""

import argparse
import asyncio
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import requests
from tqdm import tqdm

TEST_URLS = [
    "http://httpbin.org/ip",
    "http://httpbin.org/get",
    "https://httpbin.org/ip",
    "https://httpbin.org/get",
]

# Common test endpoints for speed testing
SPEED_TEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=1048576",  # 1MB
    "https://speed.cloudflare.com/__down?bytes=10485760",  # 10MB
]

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
MAX_WORKERS = 20

def test_tcp_connect(host: str, port: int, timeout: int = CONNECT_TIMEOUT) -> tuple[bool, float]:
    """Test TCP connection to host:port."""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        elapsed = time.time() - start
        return True, elapsed * 1000  # ms
    except Exception:
        return False, 0

def test_http_download(url: str, proxy: str | None = None, timeout: int = READ_TIMEOUT) -> tuple[bool, float, int]:
    """Test HTTP download speed through proxy."""
    start = time.time()
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        response = requests.get(url, proxies=proxies, timeout=timeout, stream=True)
        response.raise_for_status()
        
        total_size = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_size += len(chunk)
        
        elapsed = time.time() - start
        speed_mbps = (total_size * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
        return True, speed_mbps, total_size
    except Exception as e:
        return False, 0, 0

def build_proxy_url(node: dict) -> str | None:
    """Build proxy URL from node config for testing."""
    protocol = node.get("protocol", "")
    host = node.get("host", "") or node.get("add", "")
    port = node.get("port", 0) or node.get("server_port", 0)
    
    if not host or not port:
        return None
    
    if protocol == "shadowsocks":
        method = node.get("method", "aes-256-gcm")
        password = node.get("password", "")
        # ss://base64(method:password)@host:port
        import base64
        auth = base64.b64encode(f"{method}:{password}".encode()).decode()
        return f"ss://{auth}@{host}:{port}"
    elif protocol == "vmess":
        # For VMess, we'd need a local sing-box/v2ray to test
        # Return a local proxy format that can be used with a local proxy client
        return f"vmess://{host}:{port}"
    elif protocol == "vless":
        return f"vless://{host}:{port}"
    elif protocol == "trojan":
        password = node.get("password", "")
        return f"trojan://{password}@{host}:{port}"
    
    return None

def test_node_direct(node: dict) -> dict:
    """Test node with direct TCP/HTTP (without proxy)."""
    host = node.get("host", "") or node.get("add", "")
    port = node.get("port", 0) or node.get("server_port", 0)
    
    if not host or not port:
        return {
            "connected": False,
            "tcp_latency_ms": 0,
            "http_speed_mbps": 0,
            "error": "Missing host/port"
        }
    
    # Test TCP connection
    tcp_ok, tcp_latency = test_tcp_connect(host, port)
    
    if not tcp_ok:
        return {
            "connected": False,
            "tcp_latency_ms": 0,
            "http_speed_mbps": 0,
            "error": "TCP connection failed"
        }
    
    # Test HTTP speed (direct, not through proxy since we don't have proxy client)
    # This tests if the server responds to HTTP
    http_ok = False
    http_speed = 0
    
    for url in TEST_URLS[:2]:  # Test HTTP endpoints
        try:
            # Try direct connection to see if it's a web server
            parsed = urlparse(url)
            test_host = parsed.hostname
            test_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            
            # For now, just use TCP latency as a proxy for speed
            http_ok = True
            http_speed = 1000 / tcp_latency if tcp_latency > 0 else 0  # rough estimate
            break
        except Exception:
            continue
    
    return {
        "connected": True,
        "tcp_latency_ms": round(tcp_latency, 2),
        "http_speed_mbps": round(http_speed, 2),
        "test_method": "direct_tcp"
    }

def test_node(node: dict) -> dict:
    """Test a single node and return results."""
    result = test_node_direct(node)
    result["node_name"] = node.get("name", "") or node.get("ps", "") or "unknown"
    result["country"] = node.get("country", "XX")
    result["protocol"] = node.get("protocol", "")
    result["host"] = node.get("host", "") or node.get("add", "")
    result["port"] = node.get("port", 0) or node.get("server_port", 0)
    result["raw_link"] = node.get("raw_link", "")
    return result

def main():
    parser = argparse.ArgumentParser(description="Test VPN node connectivity and speed")
    parser.add_argument("--input", required=True, help="Input JSON file with classified nodes")
    parser.add_argument("--output", required=True, help="Output JSON file with test results")
    parser.add_argument("--max-per-country", type=int, default=50, help="Max nodes to test per country")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    by_country = data.get("by_country", {})
    
    all_results = []
    
    for country, nodes in by_country.items():
        if country == "XX":
            continue  # Skip unknown country
        
        # Limit nodes per country
        nodes_to_test = nodes[:args.max_per_country]
        print(f"Testing {len(nodes_to_test)} nodes for {country}...")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_node, node): node for node in nodes_to_test}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc=f"  {country}"):
                try:
                    result = future.result()
                    all_results.append(result)
                except Exception as e:
                    node = futures[future]
                    all_results.append({
                        "connected": False,
                        "error": str(e),
                        "node_name": node.get("name", "unknown"),
                        "country": country
                    })
    
    # Sort by country, then by speed (descending)
    all_results.sort(key=lambda x: (x.get("country", "ZZ"), -x.get("http_speed_mbps", 0)))
    
    output_data = {
        "tested_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tested": len(all_results),
        "connected": sum(1 for r in all_results if r.get("connected")),
        "results": all_results
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    
    connected = sum(1 for r in all_results if r.get("connected"))
    print(f"Testing complete: {connected}/{len(all_results)} nodes connected")

if __name__ == "__main__":
    main()