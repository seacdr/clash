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
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt"
]

TEST_URL = "https://www.google.com/generate_204"
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 测速10MB文件，测速过程限制读取前5MB
LOCAL_PORT = 10808

def fetch_links():
    links = set()
    for url in PUBLIC_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                text = r.text.strip()
                # 尝试Base64解码
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
            print(f"Fetch failed for {url}: {e}")
    return list(links)

def parse_node(link):
    try:
        if link.startswith("ss://"):
            proto = "ss"
            # 处理 ss://链接
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

def tcping(host, port, timeout=2):
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None

def build_singbox_config(node_link, local_port):
    # 构建包含单一节点的 sing-box inbound/outbound JSON 配置
    outbound = {"type": "urltest"} # 占位
    
    # 针对不同协议构建 outbound 配置
    if node_link.startswith("ss://"):
        parsed = urllib.parse.urlparse(node_link)
        # 解码 userinfo
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

def test_proxy_speed(node, local_port):
    config = build_singbox_config(node['link'], local_port)
    config_path = f"/tmp/config_{local_port}.json"
    
    with open(config_path, "w") as f:
        json.dump(config, f)

    # 启动 sing-box
    proc = subprocess.Popen(["sing-box", "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5) # 等待内核启动

    proxies = {
        "http": f"http://127.0.0.1:{local_port}",
        "https": f"http://127.0.0.1:{local_port}"
    }

    url_delay = None
    download_speed = 0  # KB/s

    # 1. Google URL 测试
    try:
        t_start = time.time()
        res = requests.get(TEST_URL, proxies=proxies, timeout=5)
        if res.status_code in [200, 204]:
            url_delay = round((time.time() - t_start) * 1000, 2)
    except Exception:
        pass

    # 2. 如果 URL 测试通过，执行下载文件测速 (最多下载5MB计算速度)
    if url_delay is not None:
        try:
            t_start = time.time()
            downloaded = 0
            with requests.get(DOWNLOAD_URL, proxies=proxies, timeout=8, stream=True) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=1024 * 64):
                    downloaded += len(chunk)
                    if downloaded >= 5 * 1024 * 1024 or (time.time() - t_start) > 6:
                        break
            dur = time.time() - t_start
            if dur > 0:
                download_speed = round((downloaded / 1024) / dur, 2) # KB/s
        except Exception:
            download_speed = 0

    # 清理进程与文件
    proc.terminate()
    proc.wait()
    if os.path.exists(config_path):
        os.remove(config_path)

    # 计算综合得分：速度优先，延迟越低加分越多
    score = (download_speed * 1000) / (url_delay + 1) if url_delay else 0
    
    return {
        "link": node['link'],
        "proto": node['proto'],
        "tcping": node['tcping'],
        "url_delay": url_delay,
        "speed": download_speed,
        "score": round(score, 2)
    }

def main():
    print("Fetching nodes from public sources...")
    raw_links = fetch_links()
    print(f"Total raw nodes fetched: {len(raw_links)}")

    parsed_nodes = []
    for link in raw_links:
        item = parse_node(link)
        if item and item['host'] and item['port']:
            parsed_nodes.append(item)

    # 第一阶段：并发 TCPing 筛选
    print("Phase 1: TCPing batch filter...")
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_node = {executor.submit(tcping, n['host'], n['port']): n for n in parsed_nodes}
        for future in concurrent.futures.as_completed(future_to_node):
            node = future_to_node[future]
            latency = future.result()
            if latency is not None:
                node['tcping'] = latency
                valid_nodes.append(node)

    print(f"TCPing passed nodes: {len(valid_nodes)}")

    # 按协议分组，每种协议取 TCPing 前 30 名进行实际代理测速（节省 GitHub Actions 时间）
    proto_groups = {"ss": [], "trojan": [], "vmess": [], "vless": [], "hy2": []}
    for n in valid_nodes:
        p = n['proto']
        if p in proto_groups:
            proto_groups[p].append(n)

    tested_results = {"ss": [], "trojan": [], "vmess": [], "vless": [], "hy2": []}

    # 第二阶段：sing-box URL & 下载速度测试
    print("Phase 2: Running sing-box proxy speed tests...")
    port_counter = LOCAL_PORT

    for proto, nodes in proto_groups.items():
        # 优先测 TCPing 最低的前 30 个
        nodes = sorted(nodes, key=lambda x: x['tcping'])[:30]
        print(f"Testing protocol [{proto}] - Count: {len(nodes)}")
        
        for n in nodes:
            res = test_proxy_speed(n, port_counter)
            if res['url_delay'] is not None and res['speed'] > 0:
                tested_results[proto].append(res)

    # 排序并提取 Top 10
    final_output = []
    final_output.append(f"# Updated at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")

    for proto, results in tested_results.items():
        # 根据 综合得分 降序排列
        top10 = sorted(results, key=lambda x: x['score'], reverse=True)[:10]
        
        final_output.append(f"==================== {proto.upper()} TOP 10 ====================")
        for idx, item in enumerate(top10, 1):
            info = f"# Rank:{idx} | TCPing:{item['tcping']}ms | GoogleDelay:{item['url_delay']}ms | Speed:{item['speed']}KB/s"
            final_output.append(f"{info}\n{item['link']}\n")

    # 保存文件
    os.makedirs("output", exist_ok=True)
    with open("output/top10.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_output))

    print("Task completed! Saved to output/top10.txt")

if __name__ == "__main__":
    main()