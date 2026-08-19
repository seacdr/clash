import os
import re
import json
import socket
import urllib.parse
import base64
import time
import subprocess
import concurrent.futures
import requests

PUBLIC_SOURCES = [
    "https://raw.githubusercontent.com/seacdr/clash/refs/heads/master/output/alvin.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt",
    #"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    #"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    #"https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt"
]

TEST_URL = "https://www.google.com/generate_204"
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=5000000"  # Cloudflare 5MB 测试文件
BASE_PORT = 10000  # 多线程 sing-box 独立本地端口起始值

def fetch_links():
    links = set()
    for url in PUBLIC_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                text = r.text.strip()
                try:
                    decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                    lines = decoded.splitlines()
                except Exception:
                    lines = text.splitlines()
                
                for line in lines:
                    line = line.strip()
                    if any(line.startswith(p) for p in ['ss://', 'trojan://', 'vmess://', 'vless://', 'hy2://', 'hysteria2://']):
                        links.add(line)
        except Exception as e:
            print(f"[Fetch Error] {url}: {e}")
    return list(links)

def parse_node(link):
    try:
        if link.startswith("ss://"):
            proto = "ss"
            main = link[5:].split('#')[0]
            if '@' in main:
                user_info, host_port = main.split('@', 1)
                host, port = host_port.split(':', 1)
            else:
                decoded = base64.b64decode(main + '==').decode('utf-8')
                user_info, host_port = decoded.split('@', 1)
                host, port = host_port.split(':', 1)
            return {"proto": proto, "host": host, "port": int(port.split('/')[0]), "link": link}
            
        elif link.startswith(("hy2://", "hysteria2://")):
            proto = "hy2"
            parsed = urllib.parse.urlparse(link)
            return {"proto": proto, "host": parsed.hostname, "port": parsed.port or 443, "link": link}
            
        elif link.startswith(("vless://", "trojan://")):
            proto = "vless" if link.startswith("vless://") else "trojan"
            parsed = urllib.parse.urlparse(link)
            return {"proto": proto, "host": parsed.hostname, "port": parsed.port or 443, "link": link}
            
        elif link.startswith("vmess://"):
            proto = "vmess"
            data = json.loads(base64.b64decode(link[8:] + '==').decode('utf-8'))
            return {"proto": proto, "host": data.get("add"), "port": int(data.get("port")), "link": link}
    except Exception:
        return None
    return None

def tcping(node, timeout=2):
    host = node['host']
    port = node['port']
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        node['tcping'] = round((time.time() - start) * 1000, 2)
        return node
    except Exception:
        return None

def build_singbox_config(node_link, local_port):
    outbound = {}
    if node_link.startswith("ss://"):
        parsed = urllib.parse.urlparse(node_link)
        try:
            userinfo = base64.b64decode(parsed.username + '==').decode('utf-8')
            method, password = userinfo.split(':', 1)
        except Exception:
            method = "aes-128-gcm"
            password = "pass"
        outbound = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "method": method,
            "password": password
        }
    elif node_link.startswith("vless://"):
        parsed = urllib.parse.urlparse(node_link)
        query = urllib.parse.parse_qs(parsed.query)
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "uuid": parsed.username,
            "flow": query.get("flow", [""])[0],
            "tls": {
                "enabled": query.get("security", [""])[0] in ["tls", "reality"],
                "server_name": query.get("sni", [parsed.hostname])[0],
                "insecure": True
            }
        }
    elif node_link.startswith("vmess://"):
        data = json.loads(base64.b64decode(node_link[8:] + '==').decode('utf-8'))
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": data.get("add"),
            "server_port": int(data.get("port")),
            "uuid": data.get("id"),
            "security": data.get("scy", "auto"),
            "alter_id": int(data.get("aid", 0))
        }
    elif node_link.startswith("trojan://"):
        parsed = urllib.parse.urlparse(node_link)
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
            "tls": {"enabled": True, "insecure": True}
        }
    elif node_link.startswith(("hy2://", "hysteria2://")):
        parsed = urllib.parse.urlparse(node_link)
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username or "",
            "tls": {"enabled": True, "insecure": True}
        }

    config = {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": local_port
        }],
        "outbounds": [outbound]
    }
    return config

def test_url_delay(args):
    node, port = args
    config = build_singbox_config(node['link'], port)
    config_path = f"/tmp/config_url_{port}.json"
    
    with open(config_path, "w") as f:
        json.dump(config, f)

    proc = subprocess.Popen(["sing-box", "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    proxies = {
        "http": f"http://127.0.0.1:{port}",
        "https": f"http://127.0.0.1:{port}"
    }

    url_delay = None
    try:
        t_start = time.time()
        res = requests.get(TEST_URL, proxies=proxies, timeout=5)
        if res.status_code in [200, 204]:
            url_delay = round((time.time() - t_start) * 1000, 2)
    except Exception:
        pass

    proc.terminate()
    proc.wait()
    if os.path.exists(config_path):
        os.remove(config_path)

    if url_delay is not None:
        node['url_delay'] = url_delay
        return node
    return None

def test_download_speed(args):
    node, port = args
    config = build_singbox_config(node['link'], port)
    config_path = f"/tmp/config_dl_{port}.json"
    
    with open(config_path, "w") as f:
        json.dump(config, f)

    proc = subprocess.Popen(["sing-box", "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    proxies = {
        "http": f"http://127.0.0.1:{port}",
        "https": f"http://127.0.0.1:{port}"
    }

    download_speed = 0  # KB/s
    try:
        t_start = time.time()
        
        # 预热参数：排除前2秒的数据，防止慢启动和握手误判
        warmup_time = 2.0
        post_warmup_bytes = 0
        post_warmup_start = None

        with requests.get(DOWNLOAD_URL, proxies=proxies, timeout=12, stream=True) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=1024 * 64):
                now = time.time()
                elapsed = now - t_start

                # 记录预热2秒后的数据
                if elapsed >= warmup_time:
                    if post_warmup_start is None:
                        post_warmup_start = now
                    post_warmup_bytes += len(chunk)

                if elapsed > 10:  # 超时保护
                    break

        if post_warmup_start and post_warmup_bytes > 0:
            duration = time.time() - post_warmup_start
            if duration > 0:
                download_speed = round((post_warmup_bytes / 1024) / duration, 2)

    except Exception:
        download_speed = 0

    proc.terminate()
    proc.wait()
    if os.path.exists(config_path):
        os.remove(config_path)

    node['speed'] = download_speed
    score = (download_speed * 1000) / (node['url_delay'] + 1)
    node['score'] = round(score, 2)
    return node

def main():
    print("=== Step 1: Fetching Raw Nodes ===")
    raw_links = fetch_links()
    print(f"Total raw nodes fetched: {len(raw_links)}")

    parsed_nodes = []
    for link in raw_links:
        item = parse_node(link)
        if item and item['host'] and item['port']:
            parsed_nodes.append(item)

    proto_groups = {"ss": [], "trojan": [], "vmess": [], "vless": [], "hy2": []}
    for n in parsed_nodes:
        p = n['proto']
        if p in proto_groups:
            proto_groups[p].append(n)

    final_results = {}

    for proto, nodes in proto_groups.items():
        print(f"\n---------------- Processing [{proto.upper()}] (Total: {len(nodes)}) ----------------")
        
        # 1. TCPing 保留前 100
        print(f"[{proto}] Stage 1: Multi-threaded TCPing Test...")
        tcp_passed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(tcping, n) for n in nodes]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    tcp_passed.append(res)
        
        tcp_passed = sorted(tcp_passed, key=lambda x: x['tcping'])[:100]
        print(f"[{proto}] Stage 1 Passed: {len(tcp_passed)} nodes (Keep Top 100)")

        if not tcp_passed:
            final_results[proto] = []
            continue

        # 2. URL 测试保留前 50
        print(f"[{proto}] Stage 2: Multi-threaded Google URL Test...")
        url_passed = []
        url_tasks = [(node, BASE_PORT + idx) for idx, node in enumerate(tcp_passed)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(test_url_delay, task) for task in url_tasks]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    url_passed.append(res)

        url_passed = sorted(url_passed, key=lambda x: x['url_delay'])[:50]
        print(f"[{proto}] Stage 2 Passed: {len(url_passed)} nodes (Keep Top 50)")

        if not url_passed:
            final_results[proto] = []
            continue

        # 3. 下载速度测试：降低并发为 5，过滤前 2 秒预热，精准计算节点速度
        print(f"[{proto}] Stage 3: Multi-threaded Download Speed Test (Warmup 2s excluded)...")
        download_results = []
        dl_tasks = [(node, BASE_PORT + 500 + idx) for idx, node in enumerate(url_passed)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_download_speed, task) for task in dl_tasks]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res['speed'] > 0:
                    download_results.append(res)

        top10 = sorted(download_results, key=lambda x: x['score'], reverse=True)[:10]
        print(f"[{proto}] Stage 3 Completed: Top {len(top10)} selected!")
        final_results[proto] = top10

    print("\n=== Saving Top 10 Results ===")
    final_output = [f"# Updated at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"]

    for proto, top10 in final_results.items():
        final_output.append(f"# ==================== {proto.upper()} TOP 10 ====================")
        for idx, item in enumerate(top10, 1):
            info = f"# Rank:{idx} | TCPing:{item['tcping']}ms | GoogleDelay:{item['url_delay']}ms | Speed:{item['speed']}KB/s | Score:{item['score']}"
            final_output.append(f"{info}\n{item['link']}\n")

    os.makedirs("output", exist_ok=True)
    # 1. 过滤掉空行和以 '#' 开头的注释/标题行
    filtered_output = [
        line for line in final_output 
        if line.strip() and not line.strip().startswith('#') and not line.strip().startswith('====')
    ]
    # 2. 写入纯节点文件 top10.txt
    with open("output/top10.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_output))
    # 3. 写入带注释与评估参数的文件 top10_notes.txt
    with open("output/top10_notes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_output))

    print("All tasks finished successfully! Output saved to output/top10.txt")

if __name__ == "__main__":
    main()