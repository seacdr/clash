#!/usr/bin/env python3
"""
Generate test log file (singbox-TEST.log) with node name + ip + speed.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any

def main():
    parser = argparse.ArgumentParser(description="Generate test log file")
    parser.add_argument("--input", required=True, help="Input JSON file with test results")
    parser.add_argument("--output", required=True, help="Output log file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    connected_nodes = [r for r in results if r.get("connected")]

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"# Sing-Box VPN Node Test Results\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total tested: {len(results)}, Connected: {len(connected_nodes)}\n")
        f.write(f"# Format: Name | Country | Protocol | IP:Port | TCP Latency(ms) | Est. Speed(Mbps)\n")
        f.write(f"{'='*100}\n")
        
        for node in connected_nodes:
            name = node.get("node_name", "unknown")[:50]
            country = node.get("country", "XX")
            protocol = node.get("protocol", "unknown")
            host = node.get("host", "unknown")
            port = node.get("port", 0)
            latency = node.get("tcp_latency_ms", 0)
            speed = node.get("http_speed_mbps", 0)
            
            f.write(f"{name} | {country} | {protocol} | {host}:{port} | {latency:.2f}ms | {speed:.2f}Mbps\n")
        
        f.write(f"\n{'='*100}\n")
        f.write(f"# Summary by country:\n")
        
        by_country = {}
        for node in connected_nodes:
            country = node.get("country", "XX")
            if country not in by_country:
                by_country[country] = []
            by_country[country].append(node)
        
        for country, nodes in sorted(by_country.items()):
            avg_latency = sum(n.get("tcp_latency_ms", 0) for n in nodes) / len(nodes)
            avg_speed = sum(n.get("http_speed_mbps", 0) for n in nodes) / len(nodes)
            f.write(f"# {country}: {len(nodes)} nodes, Avg latency: {avg_latency:.2f}ms, Avg speed: {avg_speed:.2f}Mbps\n")

    print(f"Log saved to {args.output}")

if __name__ == "__main__":
    main()