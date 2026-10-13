#!/usr/bin/env python3
"""
Search GitHub for free VPN nodes in sing-box format.
Searches public repositories updated in the last N days.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Any

import requests
from tqdm import tqdm

GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "vpn-node-fetcher/1.0"
}

SEARCH_KEYWORDS = [
    "sing-box",
    "singbox",
    "v2ray",
    "vmess",
    "vless",
    "trojan",
    "shadowsocks",
    "ss://",
    "vmess://",
    "vless://",
    "trojan://",
    "free vpn",
    "free nodes",
    "免费节点",
    "机场",
    "订阅"
]

COUNTRY_CODES = {
    "日本": "JP", "日本节点": "JP", "jp": "JP", "japan": "JP",
    "美国": "US", "美国节点": "US", "us": "US", "usa": "US", "united states": "US",
    "韩国": "KR", "韩国节点": "KR", "kr": "KR", "korea": "KR", "south korea": "KR",
    "新加坡": "SG", "新加坡节点": "SG", "sg": "SG", "singapore": "SG",
    "香港": "HK", "香港节点": "HK", "hk": "HK", "hong kong": "HK",
    "台湾": "TW", "台湾节点": "TW", "tw": "TW", "taiwan": "TW",
    "德国": "DE", "德国节点": "DE", "de": "DE", "germany": "DE",
    "英国": "GB", "英国节点": "GB", "gb": "GB", "uk": "GB", "united kingdom": "GB",
    "法国": "FR", "法国节点": "FR", "fr": "FR", "france": "FR",
    "加拿大": "CA", "加拿大节点": "CA", "ca": "CA", "canada": "CA",
    "荷兰": "NL", "荷兰节点": "NL", "nl": "NL", "netherlands": "NL",
}

def get_github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN")

def search_repositories(keyword: str, days: int, token: str | None) -> list[dict]:
    since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    query = f"{keyword} pushed:>={since_date} stars:>0"
    
    headers = HEADERS.copy()
    if token:
        headers["Authorization"] = f"token {token}"
    
    url = f"{GITHUB_API}/search/repositories"
    params = {
        "q": query,
        "sort": "updated",
        "order": "desc",
        "per_page": 30
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code == 403:
            print(f"Rate limited for keyword: {keyword}")
            return []
        response.raise_for_status()
        return response.json().get("items", [])
    except Exception as e:
        print(f"Error searching for '{keyword}': {e}")
        return []

def get_file_content(repo_full_name: str, path: str, token: str | None) -> str | None:
    headers = HEADERS.copy()
    if token:
        headers["Authorization"] = f"token {token}"
    
    url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{path}"
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        if data.get("encoding") == "base64":
            import base64
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        return data.get("content", "")
    except Exception as e:
        print(f"Error fetching {repo_full_name}/{path}: {e}")
        return None

def extract_node_links(content: str) -> list[str]:
    """Extract VPN node links from content."""
    patterns = [
        r'(ss://[^\s"\'<>]+)',
        r'(vmess://[^\s"\'<>]+)',
        r'(vless://[^\s"\'<>]+)',
        r'(trojan://[^\s"\'<>]+)',
        r'(hysteria2://[^\s"\'<>]+)',
        r'(tuic://[^\s"\'<>]+)',
    ]
    
    links = []
    for pattern in patterns:
        matches = re.findall(pattern, content)
        links.extend(matches)
    return links

def find_config_files(repo: dict, token: str | None) -> list[dict]:
    """Find configuration files in a repository."""
    repo_name = repo["full_name"]
    config_files = []
    
    # Common config file paths
    common_paths = [
        "README.md", "readme.md", "README.txt",
        "config.json", "config.yaml", "config.yml",
        "sing-box.json", "singbox.json", "sing-box.yaml", "singbox.yaml",
        "v2ray.json", "v2ray.yaml",
        "nodes.txt", "nodes.json", "nodes.yaml",
        "sub.txt", "sub.json", "subscription.txt",
        "free.txt", "free.json", "free.yaml",
        "list.txt", "list.json",
        "proxy.txt", "proxy.json",
        "servers.txt", "servers.json",
    ]
    
    # Also check for directories with config files
    tree_url = f"{GITHUB_API}/repos/{repo_name}/git/trees/main?recursive=1"
    headers = HEADERS.copy()
    if token:
        headers["Authorization"] = f"token {token}"
    
    try:
        response = requests.get(tree_url, headers=headers, timeout=30)
        if response.status_code == 200:
            tree = response.json().get("tree", [])
            for item in tree:
                if item["type"] == "blob":
                    path = item["path"]
                    name = path.lower()
                    if any(keyword in name for keyword in ["config", "node", "sub", "free", "vpn", "proxy", "server", "singbox", "sing-box", "v2ray", "clash"]):
                        if name.endswith((".json", ".yaml", ".yml", ".txt", ".md")):
                            common_paths.append(path)
    except Exception:
        pass
    
    # Remove duplicates and limit
    common_paths = list(set(common_paths))[:50]
    
    for path in common_paths:
        content = get_file_content(repo_name, path, token)
        if content:
            links = extract_node_links(content)
            if links:
                config_files.append({
                    "repo": repo_name,
                    "path": path,
                    "content": content[:50000],  # Limit size
                    "links": links,
                    "updated_at": repo["updated_at"],
                    "stars": repo["stargazers_count"]
                })
    
    return config_files

def detect_country(text: str) -> str | None:
    """Detect country from text."""
    text_lower = text.lower()
    for name, code in COUNTRY_CODES.items():
        if name.lower() in text_lower:
            return code
    return None

def main():
    parser = argparse.ArgumentParser(description="Search GitHub for free VPN nodes")
    parser.add_argument("--days", type=int, default=7, help="Days to look back")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    token = get_github_token()
    if not token:
        print("Warning: No GITHUB_TOKEN set, rate limits will be strict")

    all_results = []
    
    print(f"Searching GitHub for VPN nodes updated in last {args.days} days...")
    
    for keyword in tqdm(SEARCH_KEYWORDS, desc="Keywords"):
        repos = search_repositories(keyword, args.days, token)
        print(f"  Found {len(repos)} repos for '{keyword}'")
        
        for repo in tqdm(repos, desc=f"  Repos ({keyword})", leave=False):
            configs = find_config_files(repo, token)
            all_results.extend(configs)
            time.sleep(0.5)  # Rate limiting
    
    print(f"Total configs with nodes found: {len(all_results)}")
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()