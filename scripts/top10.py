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
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt",
    #"https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",
    #"https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt",
    #"https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt",
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


# =========================
# 性能测试参数
# =========================

TCP_ATTEMPTS = 3
URL_ATTEMPTS = 3

# 三次测试的权重：越新的结果权重越高，可自行调整。
# 例如 [0.25, 0.25, 0.50] 表示第三次占 50%。
TCP_WEIGHTS = (0.25, 0.25, 0.50)
URL_WEIGHTS = (0.25, 0.25, 0.50)

TCP_TIMEOUT = 1.5
URL_TIMEOUT = 3.5

# 单节点只启动一次 sing-box，URL 延迟测试和下载测速共用这个进程。
SINGBOX_START_TIMEOUT = 1.5
LOCAL_CONNECT_TIMEOUT = 0.15

# 下载测速：不再单独启动 sing-box。
DOWNLOAD_WARMUP = 1.0
DOWNLOAD_MAX_TIME = 6.0
DOWNLOAD_CHUNK = 128 * 1024

# 阶段筛选数量。
# TCP 先留下更多节点，URL+测速合并执行后再选最终结果。
TCP_KEEP = 100
FINAL_CANDIDATES = 50
TOP_N = 10

# 最终评分权重。
# TCP / URL 是延迟指标，Speed 是吞吐指标。
FINAL_WEIGHTS = {
    "tcp": 0.20,
    "url": 0.30,
    "speed": 0.50,
}


def weighted_average(values, weights):
    """对有效值进行加权平均。"""
    pairs = [(v, w) for v, w in zip(values, weights) if v is not None]
    if not pairs:
        return None
    weight_sum = sum(w for _, w in pairs)
    if weight_sum <= 0:
        return None
    return sum(v * w for v, w in pairs) / weight_sum


def tcping(node, timeout=TCP_TIMEOUT):
    """
    TCPing 连续 3 次。
    使用加权平均，默认最近一次权重最高。
    比原版只测一次更稳定，同时只建立/关闭 socket，不启动 sing-box。
    """
    host = node["host"]
    port = node["port"]
    samples = []

    for _ in range(TCP_ATTEMPTS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect((host, port))
            latency = (time.perf_counter() - start) * 1000
            samples.append(latency)
        except (OSError, socket.timeout):
            samples.append(None)
        finally:
            sock.close()

    valid = [x for x in samples if x is not None]
    if len(valid) < 2:
        return None

    latency = weighted_average(samples, TCP_WEIGHTS)

    # 仍保留原来的 1000ms 淘汰逻辑。
    if latency is None or latency > 1000:
        return None

    result = node.copy()
    result["tcp_samples"] = [round(x, 2) if x is not None else None for x in samples]
    result["tcping"] = round(latency, 2)
    return result


def wait_singbox_ready(port, timeout=SINGBOX_START_TIMEOUT):
    """
    不再固定 sleep(1.2)。
    sing-box 端口一旦真正监听就立即继续，明显减少空等时间。
    """
    deadline = time.perf_counter() + timeout

    while time.perf_counter() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(LOCAL_CONNECT_TIMEOUT)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.02)
        finally:
            sock.close()

    return False


def start_singbox(node_link, local_port, config_prefix):
    """启动一次 sing-box，并返回 proc/config_path。"""
    config = build_singbox_config(node_link, local_port)
    config_path = f"/tmp/{config_prefix}_{local_port}.json"

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, separators=(",", ":"))

    proc = subprocess.Popen(
        ["sing-box", "run", "-c", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not wait_singbox_ready(local_port):
        try:
            proc.terminate()
            proc.wait(timeout=0.5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            os.remove(config_path)
        except OSError:
            pass
        return None, None

    return proc, config_path


def stop_singbox(proc, config_path):
    """可靠回收 sing-box 和临时配置。"""
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=0.8)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=0.5)
            except Exception:
                pass

    if config_path:
        try:
            os.remove(config_path)
        except OSError:
            pass


def test_url_delay(session, proxies):
    """
    Google 204 连续 3 次。
    Session + 同一个 sing-box 进程复用连接，避免每次重新建立代理链路。
    """
    samples = []

    for _ in range(URL_ATTEMPTS):
        try:
            start = time.perf_counter()
            response = session.get(
                TEST_URL,
                proxies=proxies,
                timeout=URL_TIMEOUT,
                headers={"Connection": "keep-alive"},
            )
            elapsed = (time.perf_counter() - start) * 1000

            if response.status_code in (200, 204) and elapsed <= 1000:
                samples.append(elapsed)
            else:
                samples.append(None)
        except requests.RequestException:
            samples.append(None)

    valid = [x for x in samples if x is not None]

    # 3 次至少成功 2 次才认为节点稳定。
    if len(valid) < 2:
        return None

    delay = weighted_average(samples, URL_WEIGHTS)
    if delay is None or delay > 1000:
        return None

    return {
        "url_samples": [round(x, 2) if x is not None else None for x in samples],
        "url_delay": round(delay, 2),
    }


def test_download_speed(session, proxies):
    """
    下载测速与 URL 延迟测试共用同一个 sing-box + requests.Session。
    不再重复启动/关闭 sing-box，因此省掉一次完整代理启动成本。
    """
    speed = 0.0
    total_bytes = 0
    start = time.perf_counter()
    measured_start = None

    try:
        with session.get(
            DOWNLOAD_URL,
            proxies=proxies,
            timeout=(URL_TIMEOUT, DOWNLOAD_MAX_TIME + 3),
            stream=True,
            headers={"Connection": "keep-alive"},
        ) as response:
            response.raise_for_status()

            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK):
                if not chunk:
                    continue

                now = time.perf_counter()
                elapsed = now - start

                # 只统计预热后的数据。
                if elapsed >= DOWNLOAD_WARMUP:
                    if measured_start is None:
                        measured_start = now
                    total_bytes += len(chunk)

                if elapsed >= DOWNLOAD_MAX_TIME:
                    break

    except requests.RequestException:
        return 0.0

    if measured_start is not None:
        duration = time.perf_counter() - measured_start
        if duration > 0 and total_bytes > 0:
            speed = (total_bytes / 1024.0) / duration

    return round(speed, 2)


def test_url_and_download(args):
    """
    核心优化：
      1. 一个节点只启动一次 sing-box
      2. URL 连续 3 次
      3. URL 完成后直接测速
      4. 同一个 requests.Session 复用连接
      5. 不再存在原来的 Stage 2 -> Stage 3 二次启动 sing-box
    """
    node, port = args
    proc = None
    config_path = None

    try:
        proc, config_path = start_singbox(
            node["link"],
            port,
            "config_test",
        )
        if proc is None:
            return None

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }

        session = requests.Session()

        url_result = test_url_delay(session, proxies)
        if url_result is None:
            return None

        # URL 已经证明代理链路可用，立即复用当前连接进行测速。
        speed = test_download_speed(session, proxies)
        if speed <= 0:
            return None

        result = node.copy()
        result.update(url_result)
        result["speed"] = speed

        return result

    finally:
        try:
            session.close()
        except Exception:
            pass
        stop_singbox(proc, config_path)


def add_final_scores(nodes):
    """
    最终评分使用组内归一化：
      TCP 20%
      URL 30%
      Speed 50%

    延迟越低越好，速度越高越好。
    这样不会出现原公式 speed*1000/(delay+1) 过度偏向某一个量纲的问题。
    """
    if not nodes:
        return []

    min_tcp = min(n["tcping"] for n in nodes)
    min_url = min(n["url_delay"] for n in nodes)
    max_speed = max(n["speed"] for n in nodes)

    # 防止除 0。
    min_tcp = max(min_tcp, 0.001)
    min_url = max(min_url, 0.001)
    max_speed = max(max_speed, 0.001)

    results = []

    for node in nodes:
        tcp_score = min_tcp / max(node["tcping"], 0.001)
        url_score = min_url / max(node["url_delay"], 0.001)
        speed_score = node["speed"] / max_speed

        score = (
            tcp_score * FINAL_WEIGHTS["tcp"]
            + url_score * FINAL_WEIGHTS["url"]
            + speed_score * FINAL_WEIGHTS["speed"]
        ) * 100

        item = node.copy()
        item["tcp_score"] = round(tcp_score * 100, 2)
        item["url_score"] = round(url_score * 100, 2)
        item["speed_score"] = round(speed_score * 100, 2)
        item["score"] = round(score, 2)
        results.append(item)

    return results


def main():
    print("=== Step 1: Fetching Raw Nodes ===")
    raw_links = fetch_links()
    print(f"Total raw nodes fetched: {len(raw_links)}")

    parsed_nodes = []
    for link in raw_links:
        item = parse_node(link)
        if item and item["host"] and item["port"]:
            parsed_nodes.append(item)

    proto_groups = {
        "ss": [],
        "trojan": [],
        "vmess": [],
        "vless": [],
        "hy2": [],
    }

    for n in parsed_nodes:
        p = n["proto"]
        if p in proto_groups:
            proto_groups[p].append(n)

    final_results = {}

    for proto, nodes in proto_groups.items():
        print(
            f"\n---------------- Processing "
            f"[{proto.upper()}] (Total: {len(nodes)}) ----------------"
        )

        # ==========================================================
        # Stage 1：TCPing
        # ==========================================================
        print(
            f"[{proto}] Stage 1: TCPing x{TCP_ATTEMPTS} "
            f"(weights={TCP_WEIGHTS})..."
        )

        tcp_passed = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(80, max(1, len(nodes)))
        ) as executor:
            futures = [executor.submit(tcping, n) for n in nodes]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        tcp_passed.append(result)
                except Exception:
                    pass

        tcp_passed.sort(key=lambda x: x["tcping"])
        tcp_passed = tcp_passed[:TCP_KEEP]

        print(
            f"[{proto}] Stage 1 Passed: "
            f"{len(tcp_passed)} nodes (Keep Top {TCP_KEEP})"
        )

        if not tcp_passed:
            final_results[proto] = []
            continue

        # ==========================================================
        # Stage 2 + Stage 3 合并
        # ==========================================================
        #
        # 原代码：
        #   Stage 2 -> 每个节点启动一次 sing-box -> URL
        #   Stage 3 -> 再启动一次 sing-box -> Download
        #
        # 现在：
        #   每个节点只启动一次 sing-box
        #   URL x3 -> Download
        #
        print(
            f"[{proto}] Stage 2+3: URL x{URL_ATTEMPTS} "
            f"+ Download in ONE sing-box session..."
        )

        test_results = []

        # 50 并发可能导致 CPU / FD / sing-box 进程压力。
        # 这里默认 12，可根据机器性能调整。
        test_workers = min(12, max(1, len(tcp_passed)))

        test_tasks = [
            (node, BASE_PORT + 1000 + idx)
            for idx, node in enumerate(tcp_passed)
        ]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=test_workers
        ) as executor:
            futures = [
                executor.submit(test_url_and_download, task)
                for task in test_tasks
            ]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        test_results.append(result)
                except Exception:
                    pass

        print(
            f"[{proto}] URL+Speed Passed: "
            f"{len(test_results)} nodes"
        )

        if not test_results:
            final_results[proto] = []
            continue

        # 先按粗略综合指标缩小候选集，避免所有节点进入最终评分。
        # speed 越高越好，latency 越低越好。
        test_results.sort(
            key=lambda x: (
                x["speed"] / max(x["url_delay"], 1.0)
            ),
            reverse=True,
        )
        candidates = test_results[:FINAL_CANDIDATES]

        # 最终使用 TCP + URL + Speed 三项权重。
        scored = add_final_scores(candidates)
        top10 = sorted(
            scored,
            key=lambda x: x["score"],
            reverse=True,
        )[:TOP_N]

        print(
            f"[{proto}] Completed: "
            f"Top {len(top10)} selected!"
        )

        final_results[proto] = top10

    # ==============================================================
    # 保存结果
    # ==============================================================
    print("\n=== Saving Top 10 Results ===")

    final_output = [
        f"# Updated at: "
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    ]

    for proto, top10 in final_results.items():
        final_output.append(
            f"# ==================== {proto.upper()} TOP 10 ===================="
        )

        for idx, item in enumerate(top10, 1):
            info = (
                f"# Rank:{idx} | "
                f"TCP:{item['tcping']}ms "
                f"(samples={item['tcp_samples']}) | "
                f"GoogleDelay:{item['url_delay']}ms "
                f"(samples={item['url_samples']}) | "
                f"Speed:{item['speed']}KB/s | "
                f"Score:{item['score']} "
                f"[TCP:{item['tcp_score']}, "
                f"URL:{item['url_score']}, "
                f"Speed:{item['speed_score']}]"
            )

            final_output.append(
                f"{info}\n{item['link']}\n"
            )

    os.makedirs("output", exist_ok=True)

    filtered_output = [
        line
        for line in final_output
        if line.strip()
        and not line.strip().startswith("#")
        and not line.strip().startswith("====")
    ]

    with open("output/top10.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_output))

    with open("output/top10_notes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_output))

    print(
        "All tasks finished successfully! "
        "Output saved to output/top10.txt"
    )


if __name__ == "__main__":
    main()
