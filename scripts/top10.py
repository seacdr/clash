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
import threading
import traceback
from datetime import datetime

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

LOG_FILE = "output/test_detailed.log"
LOG_LOCK = threading.Lock()

def log(message, level="INFO"):
    """线程安全的控制台 + 文件日志。每个节点的成功/失败都保留。"""
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] [{level}] {message}"
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with LOG_LOCK:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass

def node_label(node):
    """不记录完整 URI，避免把 UUID/密码等敏感字段写进日志。"""
    return f"{node.get('proto','?').upper()} {node.get('host','?')}:{node.get('port','?')}"

def short_error(exc):
    return f"{type(exc).__name__}: {exc}"

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
            log(f"[Fetch Error] {url}: {e}")
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
    "tcp": 0.01,
    "url": 0.01,
    "speed": 0.98,
}



def _b64decode_text(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value).decode("utf-8")

def _parse_transport(q):
    network = q.get("type") or q.get("network") or "tcp"
    if network == "ws":
        return {
            "type": "ws",
            "path": q.get("path", "/"),
            **({"headers": {"Host": q.get("host")}} if q.get("host") else {}),
        }
    if network == "grpc":
        return {
            "type": "grpc",
            "service_name": q.get("serviceName") or q.get("service_name", ""),
        }
    if network in ("http", "h2"):
        return {
            "type": "http",
            "path": q.get("path", "/"),
            **({"host": [q.get("host")]} if q.get("host") else {}),
        }
    return {"type": "tcp"}

def _parse_tls(q):
    security = q.get("security", "")
    if security not in ("tls", "reality"):
        return None

    tls = {
        "enabled": True,
        "server_name": q.get("sni") or q.get("serverName") or q.get("host"),
    }

    if q.get("alpn"):
        tls["alpn"] = q.get("alpn").split(",")

    if q.get("insecure") in ("1", "true", "True"):
        tls["insecure"] = True

    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk") or q.get("publicKey", ""),
            "short_id": q.get("sid") or q.get("shortId", ""),
        }
        if q.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}

    return tls

def build_singbox_config(node_link, local_port):
    """
    将常见 SS / VMess / VLESS / Trojan / Hysteria2 URI 转成 sing-box
    最小可用测试配置。原文件调用了这个函数，但函数本身缺失，这是
    Stage 2+3 全部失败的直接原因之一。
    """
    parsed = urllib.parse.urlparse(node_link)
    scheme = parsed.scheme.lower()
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    q = {k: v[-1] for k, v in q.items()}

    outbound = None

    if scheme == "ss":
        main = node_link[5:].split("#", 1)[0]
        if "@" in main:
            encoded_user, host_port = main.rsplit("@", 1)
            host, port = host_port.rsplit(":", 1)
            try:
                user = _b64decode_text(encoded_user)
            except Exception:
                user = urllib.parse.unquote(encoded_user)
            if ":" not in user:
                raise ValueError("SS URI 缺少 method:password")
            method, password = user.split(":", 1)
        else:
            decoded = _b64decode_text(main)
            user, host_port = decoded.rsplit("@", 1)
            host, port = host_port.rsplit(":", 1)
            method, password = user.split(":", 1)

        outbound = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password,
        }

    elif scheme == "vmess":
        data = json.loads(_b64decode_text(node_link[8:]))
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": data["add"],
            "server_port": int(data.get("port", 443)),
            "uuid": data["id"],
            "security": data.get("scy") or data.get("security", "auto"),
        }
        network = data.get("net", "tcp")
        if network == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": data.get("path", "/"),
                **({"headers": {"Host": data["host"]}} if data.get("host") else {}),
            }
        elif network == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": data.get("path", ""),
            }
        if data.get("tls", "").lower() in ("tls", "1", "true"):
            outbound["tls"] = {
                "enabled": True,
                "server_name": data.get("sni") or data.get("host") or data["add"],
            }

    elif scheme == "vless":
        if not parsed.username or not parsed.hostname:
            raise ValueError("VLESS URI 缺少 UUID 或服务器")
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "uuid": urllib.parse.unquote(parsed.username),
        }
        if q.get("flow"):
            outbound["flow"] = q["flow"]
        tls = _parse_tls(q)
        if tls:
            outbound["tls"] = tls
        outbound["transport"] = _parse_transport(q)

    elif scheme == "trojan":
        if not parsed.username or not parsed.hostname:
            raise ValueError("Trojan URI 缺少 password 或服务器")
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": urllib.parse.unquote(parsed.username),
        }
        tls = _parse_tls(q) or {
            "enabled": True,
            "server_name": q.get("sni") or parsed.hostname,
        }
        outbound["tls"] = tls
        if q.get("type") or q.get("network"):
            outbound["transport"] = _parse_transport(q)

    elif scheme in ("hy2", "hysteria2"):
        password = urllib.parse.unquote(parsed.username or "")
        if not parsed.hostname:
            raise ValueError("Hysteria2 URI 缺少服务器")
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": password,
        }
        tls = {
            "enabled": True,
            "server_name": q.get("sni") or parsed.hostname,
        }
        if q.get("insecure") in ("1", "true", "True"):
            tls["insecure"] = True
        outbound["tls"] = tls

    else:
        raise ValueError(f"不支持的协议: {scheme}")

    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": int(local_port),
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
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
    """TCPing x3；无论成功/失败都记录每一次测试。"""
    label = node_label(node)
    host, port = node["host"], node["port"]
    samples = []

    for attempt in range(1, TCP_ATTEMPTS + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect((host, port))
            latency = (time.perf_counter() - start) * 1000
            samples.append(latency)
            #log(f"[TCP] {label} attempt={attempt}/{TCP_ATTEMPTS} PASS {latency:.2f}ms")
        except (OSError, socket.timeout) as e:
            samples.append(None)
            #log(f"[TCP] {label} attempt={attempt}/{TCP_ATTEMPTS} FAIL {short_error(e)}", "WARN")
        except Exception as e:
            samples.append(None)
            #log(f"[TCP] {label} attempt={attempt}/{TCP_ATTEMPTS} EXCEPTION {short_error(e)}", "ERROR")
        finally:
            sock.close()

    valid = [x for x in samples if x is not None]
    if len(valid) < 2:
        #log(f"[TCP] {label} REJECT valid={len(valid)}/{TCP_ATTEMPTS}, samples={samples}", "WARN")
        return None

    latency = weighted_average(samples, TCP_WEIGHTS)
    if latency is None or latency > 1000:
        #log(f"[TCP] {label} REJECT weighted={latency}ms (>1000ms)", "WARN")
        return None

    result = node.copy()
    result["tcp_samples"] = [round(x, 2) if x is not None else None for x in samples]
    result["tcping"] = round(latency, 2)
    #log(f"[TCP] {label} PASS weighted={latency:.2f}ms samples={result['tcp_samples']}")
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


def start_singbox(node_link, local_port, config_prefix, label=""):
    """启动 sing-box；配置错误/启动错误都写入详细日志。"""
    config_path = f"/tmp/{config_prefix}_{local_port}.json"
    try:
        config = build_singbox_config(node_link, local_port)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

        # 先让 sing-box 自己校验配置，避免错误被 DEVNULL 吞掉。
        check = subprocess.run(
            ["sing-box", "check", "-c", config_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or "").strip()
            #log(f"[SBOX] {label} CONFIG FAIL: {detail[-2000:]}", "ERROR")
            return None, None

        proc = subprocess.Popen(
            ["sing-box", "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not wait_singbox_ready(local_port):
            #log(f"[SBOX] {label} START FAIL: local port {local_port} not ready; pid={proc.pid}", "ERROR")
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=0.5)
                except Exception:
                    pass
            return None, None

        #log(f"[SBOX] {label} START PASS local=127.0.0.1:{local_port} pid={proc.pid}")
        return proc, config_path

    except FileNotFoundError as e:
        log(f"[SBOX] {label} START FAIL: sing-box executable not found: {e}", "ERROR")
    except subprocess.TimeoutExpired as e:
        log(f"[SBOX] {label} CONFIG CHECK TIMEOUT: {e}", "ERROR")
    except Exception as e:
        log(f"[SBOX] {label} START EXCEPTION: {short_error(e)}", "ERROR")
        log(traceback.format_exc().rstrip(), "ERROR")
    return None, None


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


def test_url_delay(session, proxies, label=""):
    """Google 204 x3；记录状态码、耗时、异常。"""
    samples = []

    for attempt in range(1, URL_ATTEMPTS + 1):
        try:
            start = time.perf_counter()
            response = session.get(
                TEST_URL,
                proxies=proxies,
                timeout=URL_TIMEOUT,
                headers={"Connection": "keep-alive"},
            )
            elapsed = (time.perf_counter() - start) * 1000

            ok = response.status_code in (200, 204) and elapsed <= 1000
            if ok:
                samples.append(elapsed)
                #log(f"[URL] {label} attempt={attempt}/{URL_ATTEMPTS} PASS status={response.status_code} {elapsed:.2f}ms")
            else:
                samples.append(None)
                #log(
                #    f"[URL] {label} attempt={attempt}/{URL_ATTEMPTS} FAIL "
                #    f"status={response.status_code} {elapsed:.2f}ms body={response.text[:120]!r}",
                #    "WARN",
                #)
        except requests.RequestException as e:
            samples.append(None)
            #log(f"[URL] {label} attempt={attempt}/{URL_ATTEMPTS} FAIL {short_error(e)}", "WARN")
        except Exception as e:
            samples.append(None)
            #log(f"[URL] {label} attempt={attempt}/{URL_ATTEMPTS} EXCEPTION {short_error(e)}", "ERROR")

    valid = [x for x in samples if x is not None]
    if len(valid) < 2:
        #log(f"[URL] {label} REJECT valid={len(valid)}/{URL_ATTEMPTS}, samples={samples}", "WARN")
        return None

    delay = weighted_average(samples, URL_WEIGHTS)
    if delay is None or delay > 1000:
        #log(f"[URL] {label} REJECT weighted={delay}ms", "WARN")
        return None

    result = {
        "url_samples": [round(x, 2) if x is not None else None for x in samples],
        "url_delay": round(delay, 2),
    }
    #log(f"[URL] {label} PASS weighted={delay:.2f}ms samples={result['url_samples']}")
    return result


def test_download_speed(session, proxies, label=""):
    """下载测速；记录 HTTP 状态、字节数、耗时、异常。"""
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
            #log(f"[DL] {label} HTTP status={response.status_code} content-length={response.headers.get('Content-Length')}")
            response.raise_for_status()

            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK):
                if not chunk:
                    continue

                now = time.perf_counter()
                elapsed = now - start
                if elapsed >= DOWNLOAD_WARMUP:
                    if measured_start is None:
                        measured_start = now
                    total_bytes += len(chunk)

                if elapsed >= DOWNLOAD_MAX_TIME:
                    break

    except requests.RequestException as e:
        #log(f"[DL] {label} FAIL {short_error(e)} bytes={total_bytes}", "WARN")
        return 0.0
    except Exception as e:
        #log(f"[DL] {label} EXCEPTION {short_error(e)}", "ERROR")
        return 0.0

    if measured_start is not None:
        duration = time.perf_counter() - measured_start
        if duration > 0 and total_bytes > 0:
            speed = (total_bytes / 1024.0) / duration

    speed = round(speed, 2)
    if speed > 0:
        log(f"[DL] {label} PASS speed={speed}KB/s bytes={total_bytes} measured={max(0, time.perf_counter()-measured_start if measured_start else 0):.2f}s")
    else:
        log(f"[DL] {label} FAIL speed=0 bytes={total_bytes}", "WARN")
    return speed


def test_url_and_download(args):
    """一个节点一次 sing-box：启动 -> URL x3 -> 下载 -> 统一记录最终结果。"""
    node, port, node_index = args
    label = f"#{node_index} {node_label(node)}"
    proc = None
    config_path = None
    session = requests.Session()

    details = {
        "tcp": "UNKNOWN",
        "tcp_samples": [],
        "tcp_avg": None,

        "sbox": "NOT_TESTED",
        "sbox_error": "",

        "url": "NOT_TESTED",
        "url_samples": [],
        "url_avg": None,

        "speed": "NOT_TESTED",
        "speed_value": 0,

        "result": "FAIL",
        "reason": "",
    }

    try:
        # =========================
        # TCP
        # =========================
        details["tcp"] = "PASS"

        if node.get("tcp_samples"):
            details["tcp_samples"] = node["tcp_samples"]

        if node.get("tcping") is not None:
            details["tcp_avg"] = node["tcping"]

        # =========================
        # sing-box
        # =========================
        try:
            proc, config_path = start_singbox(
                node["link"],
                port,
                "config_test",
                label=label
            )

            if proc is None:
                details["sbox"] = "FAIL"
                details["sbox_error"] = "start/config failed"
                details["reason"] = "SBOX"
                return None

            details["sbox"] = "PASS"

        except Exception as e:
            details["sbox"] = "FAIL"
            details["sbox_error"] = short_error(e)
            details["reason"] = "SBOX"
            return None

        # =========================
        # URL
        # =========================
        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }

        try:
            url_result = test_url_delay(
                session,
                proxies,
                label=label
            )

            if url_result is None:
                details["url"] = "FAIL"
                details["reason"] = "URL"
                return None

            details["url"] = "PASS"
            details["url_samples"] = url_result["url_samples"]
            details["url_avg"] = url_result["url_delay"]

        except Exception as e:
            details["url"] = "FAIL"
            details["reason"] = "URL"
            return None

        # =========================
        # Download
        # =========================
        try:
            speed = test_download_speed(
                session,
                proxies,
                label=label
            )

            if speed <= 0:
                details["speed"] = "FAIL"
                details["reason"] = "DOWNLOAD"
                return None

            details["speed"] = "PASS"
            details["speed_value"] = speed

        except Exception as e:
            details["speed"] = "FAIL"
            details["reason"] = "DOWNLOAD"
            return None

        # =========================
        # 全部成功
        # =========================
        details["result"] = "PASS"
        details["reason"] = ""

        result = node.copy()
        result.update(url_result)
        result["speed"] = speed

        return result

    except Exception as e:
        details["result"] = "FAIL"
        details["reason"] = "EXCEPTION"

    finally:
        # ==========================================================
        # 一个节点只在这里记录一次日志
        # ==========================================================
        tcp_text = (
            f"{details['tcp']} "
            f"{details['tcp_samples']} "
            f"avg={details['tcp_avg']}ms"
        )

        sbox_text = details["sbox"]

        if details["sbox_error"]:
            sbox_text += f"({details['sbox_error']})"

        url_text = details["url"]

        if details["url_samples"]:
            url_text += (
                f" {details['url_samples']} "
                f"avg={details['url_avg']}ms"
            )

        speed_text = details["speed"]

        if details["speed_value"]:
            speed_text += f" {details['speed_value']}KB/s"

        log(
            f"[NODE] {label} | "
            f"TCP={tcp_text} | "
            f"SBOX={sbox_text} | "
            f"URL={url_text} | "
            f"SPEED={speed_text} | "
            f"RESULT={details['result']}"
            + (
                f"({details['reason']})"
                if details["reason"]
                else ""
            )
        )

        session.close()
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
    min_tcp = max(min_tcp, 1)
    min_url = max(min_url, 1)
    max_speed = max(max_speed, 1)

    results = []

    for node in nodes:
        tcp_score = min_tcp / max(node["tcping"], 1)
        url_score = min_url / max(node["url_delay"], 1)
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
    os.makedirs("output", exist_ok=True)
    with LOG_LOCK:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Detailed test log started {datetime.now().isoformat()} ===\\n")
    log("=== Step 1: Fetching Raw Nodes ===")
    raw_links = fetch_links()
    log(f"Total raw nodes fetched: {len(raw_links)}")

    parsed_nodes = []
    for link in raw_links:
        item = parse_node(link)
        if item and item["host"] and item["port"]:
            item["_node_index"] = len(parsed_nodes) + 1
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
        log(
            f"\n---------------- Processing "
            f"[{proto.upper()}] (Total: {len(nodes)}) ----------------"
        )

        # ==========================================================
        # Stage 1：TCPing
        # ==========================================================
        log(
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
                except Exception as e:
                    log(f"[TCP] FUTURE EXCEPTION {short_error(e)}", "ERROR")
                    log(traceback.format_exc().rstrip(), "ERROR")

        tcp_passed.sort(key=lambda x: x["tcping"])
        tcp_passed = tcp_passed[:TCP_KEEP]

        log(
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
        log(
            f"[{proto}] Stage 2+3: URL x{URL_ATTEMPTS} "
            f"+ Download in ONE sing-box session..."
        )

        test_results = []

        # 50 并发可能导致 CPU / FD / sing-box 进程压力。
        # 这里默认 12，可根据机器性能调整。
        test_workers = min(12, max(1, len(tcp_passed)))

        test_tasks = [
            (node, BASE_PORT + 1000 + idx, node.get("_node_index", idx + 1))
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
                except Exception as e:
                    log(f"[STAGE2+3] FUTURE EXCEPTION {short_error(e)}", "ERROR")
                    log(traceback.format_exc().rstrip(), "ERROR")

        log(
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

        log(
            f"[{proto}] Completed: "
            f"Top {len(top10)} selected!"
        )

        final_results[proto] = top10

    # ==============================================================
    # 保存结果
    # ==============================================================
    log("\n=== Saving Top 10 Results ===")

    final_output = [
        f"# Updated at: "
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    ]

    for proto, top10 in final_results.items():
        final_output.append(
            f"# ==================== {proto.upper()} TOP 10 ===================="
        )

        for idx, item in enumerate(top10, 1):
            item = {k: v for k, v in item.items() if not k.startswith("_")}
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

    log(
        "All tasks finished successfully! "
        "Output saved to output/top10.txt"
    )


if __name__ == "__main__":
    main()
