#!/usr/bin/env python3
"""
Generate top 10 fastest nodes per country as sing-box JSON configs.
"""

import argparse
import json
import sys
from typing import Any

def main():
    parser = argparse.ArgumentParser(description="Generate top 10 nodes per country")
    parser.add_argument("--input", required=True, help="Input JSON file with test results")
    parser.add_argument("--output-dir", required=True, help="Output directory for country JSON files")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    connected_nodes = [r for r in results if r.get("connected")]

    # Group by country
    by_country = {}
    for node in connected_nodes:
        country = node.get("country", "XX")
        if country not in by_country:
            by_country[country] = []
        by_country[country].append(node)

    # Sort each country by speed (descending) and take top 10
    for country, nodes in by_country.items():
        nodes.sort(key=lambda x: x.get("http_speed_mbps", 0), reverse=True)
        top10 = nodes[:10]
        
        # Build sing-box outbound configs
        outbounds = []
        for node in top10:
            # Reconstruct sing-box config from original node data
            # We need to get the original singbox config from the parsed data
            # For now, build from test result data
            outbound = build_singbox_outbound(node)
            if outbound:
                outbounds.append(outbound)
        
        # Create sing-box config
        config = {
            "outbounds": outbounds
        }
        
        output_file = f"{args.output_dir}/singbox-{country}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        
        print(f"Generated {output_file} with {len(outbounds)} nodes")

def build_singbox_outbound(node: dict) -> dict | None:
    """Build sing-box outbound config from test result."""
    protocol = node.get("protocol", "")
    name = node.get("node_name", "unknown")
    host = node.get("host", "")
    port = node.get("port", 0)
    
    if not host or not port:
        return None
    
    # Clean name for tag
    tag = f"{name}-{host}:{port}".replace(" ", "_").replace("/", "_")[:64]
    
    if protocol == "vmess":
        return {
            "type": "vmess",
            "tag": tag,
            "server": host,
            "server_port": port,
            "uuid": node.get("uuid", ""),
            "security": "auto",
            "alter_id": 0
        }
    elif protocol == "vless":
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": port,
            "uuid": node.get("uuid", ""),
            "flow": "",
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": True
            }
        }
    elif protocol == "trojan":
        return {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": port,
            "password": node.get("password", ""),
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": True
            }
        }
    elif protocol == "shadowsocks":
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": host,
            "server_port": port,
            "method": node.get("method", "aes-256-gcm"),
            "password": node.get("password", "")
        }
    
    return None

if __name__ == "__main__":
    main()