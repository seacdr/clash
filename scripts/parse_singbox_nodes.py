#!/usr/bin/env python3
"""
Parse sing-box format nodes from raw content and classify by country.
"""

import argparse
import base64
import json
import re
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

COUNTRY_CODES = {
    "日本": "JP", "日本节点": "JP", "jp": "JP", "japan": "JP", "🇯🇵": "JP",
    "美国": "US", "美国节点": "US", "us": "US", "usa": "US", "united states": "US", "🇺🇸": "US",
    "韩国": "KR", "韩国节点": "KR", "kr": "KR", "korea": "KR", "south korea": "KR", "🇰🇷": "KR",
    "新加坡": "SG", "新加坡节点": "SG", "sg": "SG", "singapore": "SG", "🇸🇬": "SG",
    "香港": "HK", "香港节点": "HK", "hk": "HK", "hong kong": "HK", "🇭🇰": "HK",
    "台湾": "TW", "台湾节点": "TW", "tw": "TW", "taiwan": "TW", "🇹🇼": "TW",
    "德国": "DE", "德国节点": "DE", "de": "DE", "germany": "DE", "🇩🇪": "DE",
    "英国": "GB", "英国节点": "GB", "gb": "GB", "uk": "GB", "united kingdom": "GB", "🇬🇧": "GB",
    "法国": "FR", "法国节点": "FR", "fr": "FR", "france": "FR", "🇫🇷": "FR",
    "加拿大": "CA", "加拿大节点": "CA", "ca": "CA", "canada": "CA", "🇨🇦": "CA",
    "荷兰": "NL", "荷兰节点": "NL", "nl": "NL", "netherlands": "NL", "🇳🇱": "NL",
}

def decode_vmess(link: str) -> dict | None:
    """Decode vmess:// link."""
    try:
        b64 = link[8:]  # Remove 'vmess://'
        # Add padding if needed
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        decoded = base64.b64decode(b64).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None

def decode_vless(link: str) -> dict | None:
    """Parse vless:// link."""
    try:
        parsed = urlparse(link)
        # vless://uuid@host:port?params#name
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        params = parse_qs(parsed.query)
        name = parsed.fragment
        
        return {
            "uuid": uuid,
            "host": host,
            "port": port,
            "params": {k: v[0] for k, v in params.items()},
            "name": name,
            "type": "vless"
        }
    except Exception:
        return None

def decode_trojan(link: str) -> dict | None:
    """Parse trojan:// link."""
    try:
        parsed = urlparse(link)
        # trojan://password@host:port?params#name
        password = parsed.username
        host = parsed.hostname
        port = parsed.port
        params = parse_qs(parsed.query)
        name = parsed.fragment
        
        return {
            "password": password,
            "host": host,
            "port": port,
            "params": {k: v[0] for k, v in params.items()},
            "name": name,
            "type": "trojan"
        }
    except Exception:
        return None

def decode_ss(link: str) -> dict | None:
    """Parse ss:// link."""
    try:
        # ss://base64@host:port#name or ss://base64#name
        link = link[5:]  # Remove 'ss://'
        if "@" in link:
            auth, rest = link.split("@", 1)
            host_port, *name_parts = rest.split("#")
            name = name_parts[0] if name_parts else ""
        else:
            auth = link
            host_port = ""
            name = ""
        
        # Decode auth part
        auth += "=" * ((4 - len(auth) % 4) % 4)
        decoded = base64.b64decode(auth).decode("utf-8")
        # format: method:password
        if ":" in decoded:
            method, password = decoded.split(":", 1)
        else:
            method, password = "unknown", decoded
        
        host = ""
        port = 0
        if host_port:
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
        
        return {
            "method": method,
            "password": password,
            "host": host,
            "port": port,
            "name": name,
            "type": "shadowsocks"
        }
    except Exception:
        return None

def parse_node_link(link: str) -> dict | None:
    """Parse any supported node link."""
    if link.startswith("vmess://"):
        data = decode_vmess(link)
        if data:
            data["raw_link"] = link
            data["protocol"] = "vmess"
        return data
    elif link.startswith("vless://"):
        data = decode_vless(link)
        if data:
            data["raw_link"] = link
            data["protocol"] = "vless"
        return data
    elif link.startswith("trojan://"):
        data = decode_trojan(link)
        if data:
            data["raw_link"] = link
            data["protocol"] = "trojan"
        return data
    elif link.startswith("ss://"):
        data = decode_ss(link)
        if data:
            data["raw_link"] = link
            data["protocol"] = "shadowsocks"
        return data
    return None

def detect_country_from_node(node: dict) -> str:
    """Detect country from node name or host."""
    # Check name
    name = node.get("name", "") or node.get("ps", "") or node.get("remarks", "")
    if name:
        country = detect_country(name)
        if country:
            return country
    
    # Check host
    host = node.get("host", "") or node.get("add", "")
    if host:
        country = detect_country(host)
        if country:
            return country
    
    # Check sni
    sni = node.get("sni", "") or node.get("servername", "")
    if sni:
        country = detect_country(sni)
        if country:
            return country
    
    return "XX"

def detect_country(text: str) -> str | None:
    """Detect country code from text."""
    text_lower = text.lower()
    for name, code in COUNTRY_CODES.items():
        if name.lower() in text_lower:
            return code
    return None

def convert_to_singbox(node: dict) -> dict:
    """Convert parsed node to sing-box outbound format."""
    protocol = node.get("protocol", "")
    
    if protocol == "vmess":
        return {
            "type": "vmess",
            "tag": node.get("name", node.get("ps", "vmess")),
            "server": node.get("add", node.get("host", "")),
            "server_port": int(node.get("port", node.get("server_port", 0))),
            "uuid": node.get("id", node.get("uuid", "")),
            "security": node.get("scy", node.get("security", "auto")),
            "alter_id": int(node.get("aid", node.get("alter_id", 0))),
            "tls": {
                "enabled": node.get("tls", "") == "tls",
                "server_name": node.get("sni", node.get("host", "")),
                "insecure": node.get("allowInsecure", False)
            } if node.get("tls", "") == "tls" else None,
            "transport": {
                "type": node.get("net", "tcp"),
                "path": node.get("path", ""),
                "headers": {"Host": node.get("host", "")} if node.get("host") else {}
            } if node.get("net", "tcp") != "tcp" else None
        }
    elif protocol == "vless":
        return {
            "type": "vless",
            "tag": node.get("name", "vless"),
            "server": node.get("host", ""),
            "server_port": int(node.get("port", 0)),
            "uuid": node.get("uuid", ""),
            "flow": node.get("params", {}).get("flow", ""),
            "tls": {
                "enabled": True,
                "server_name": node.get("params", {}).get("sni", node.get("host", "")),
                "insecure": node.get("params", {}).get("allowInsecure", "false") == "true"
            },
            "transport": {
                "type": node.get("params", {}).get("type", "tcp"),
                "path": node.get("params", {}).get("path", ""),
                "headers": {"Host": node.get("params", {}).get("host", "")} if node.get("params", {}).get("host") else {}
            } if node.get("params", {}).get("type", "tcp") != "tcp" else None
        }
    elif protocol == "trojan":
        return {
            "type": "trojan",
            "tag": node.get("name", "trojan"),
            "server": node.get("host", ""),
            "server_port": int(node.get("port", 0)),
            "password": node.get("password", ""),
            "tls": {
                "enabled": True,
                "server_name": node.get("params", {}).get("sni", node.get("host", "")),
                "insecure": node.get("params", {}).get("allowInsecure", "false") == "true"
            },
            "transport": {
                "type": node.get("params", {}).get("type", "tcp"),
                "path": node.get("params", {}).get("path", ""),
                "headers": {"Host": node.get("params", {}).get("host", "")} if node.get("params", {}).get("host") else {}
            } if node.get("params", {}).get("type", "tcp") != "tcp" else None
        }
    elif protocol == "shadowsocks":
        return {
            "type": "shadowsocks",
            "tag": node.get("name", "ss"),
            "server": node.get("host", ""),
            "server_port": int(node.get("port", 0)),
            "method": node.get("method", "aes-256-gcm"),
            "password": node.get("password", "")
        }
    return {}

def main():
    parser = argparse.ArgumentParser(description="Parse and classify sing-box nodes")
    parser.add_argument("--input", required=True, help="Input JSON file from search")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    all_nodes = []
    seen_links = set()

    for config in raw_data:
        repo = config.get("repo", "")
        path = config.get("path", "")
        links = config.get("links", [])
        
        for link in links:
            if link in seen_links:
                continue
            seen_links.add(link)
            
            parsed = parse_node_link(link)
            if not parsed:
                continue
            
            parsed["source_repo"] = repo
            parsed["source_path"] = path
            parsed["country"] = detect_country_from_node(parsed)
            parsed["singbox"] = convert_to_singbox(parsed)
            all_nodes.append(parsed)

    # Group by country
    by_country = {}
    for node in all_nodes:
        country = node["country"]
        if country not in by_country:
            by_country[country] = []
        by_country[country].append(node)

    result = {
        "total_nodes": len(all_nodes),
        "countries": {c: len(nodes) for c, nodes in by_country.items()},
        "nodes": all_nodes,
        "by_country": by_country
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Parsed {len(all_nodes)} unique nodes")
    for country, nodes in by_country.items():
        print(f"  {country}: {len(nodes)} nodes")

if __name__ == "__main__":
    main()