#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pipeline.py — 节点 抓取 → 安全筛选/去重 → 延迟+国家 → 2MB 测速 → 排序/分国家输出
目标环境: Redmi AX6 / ImmortalWrt 25.12 / sing-box 1.12 / python3 3.13 (仅标准库)

用法: python3 pipeline.py run [--stage all|fetch,delay,download,output] [--config config.json] [-v]

设计要点(时间效率优先):
  1. fetch    多源并发下载, 解析→安全筛选→去重 一次流式完成, 实时写 top-all.txt
  2. delay    不做 Python 直连 DNS / TCP 预探测；直接由 sing-box 连接节点，减少重复网络探测
              → 每批 N 个节点合并进【一个】sing-box 进程，单次代理请求同时得到延迟 + 出口国家
  3. download 仅对每国延迟最低的前 K 个节点测速, 默认 2MiB, 低并发保证带宽测得准
  4. output   纯本地排序/重命名, 原子写入, 空结果不覆盖旧文件
  5. 跳过 delay 时可通过 paths.delay_cache_url 复用 GitHub Actions 发布的延迟筛选结果
所有网络动作均直连(不使用任何代理), 测试用 sing-box 不监听外网, 仅 127.0.0.1 随机端口。
"""
from __future__ import annotations

import argparse
import atexit
import base64
import gc
import glob
import json
import logging
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, quote, unquote, urlsplit

try:
    import ssl
except ImportError:  # 未安装 python3-openssl
    ssl = None

HERE = os.path.dirname(os.path.abspath(__file__))

# ════════════════════════════════════════════════════════════════════
# 配置
# ════════════════════════════════════════════════════════════════════
DEFAULT_CONFIG = {
    "paths": {  # 默认路径, 可在 config.json 里覆盖
        "tmp": "/tmp/sing-box",
        "out": "/tmp/sing-box",
        "singbox": "sing-box",
        # AX6 跳过 delay 阶段时，从已发布的延迟筛选结果恢复候选节点；留空表示仅使用本地缓存。
        "delay_cache_url": "",
    },
    "limits": {"mem_mb": 100, "nice": 10},  # 内存软限制(MB), 进程优先级(nice)
    # 避免被路由器上已运行的 sing-box 透明代理劫持:
    #   mark: 给测试流量打 fwmark(SO_MARK/routing_mark), 需在主 sing-box/nft 规则里放行该 mark
    #   bind_interface: 测试用 sing-box 出站绑定的物理口(如 wan / pppoe-wan), 绕过 tun/策略路由
    "isolation": {"mark": 0, "bind_interface": "pppoe-wan"}, # 0=不打 mark, ""=不绑定接口
    "name_style": "code",  # zh=中文国名(美国_01_120ms)  code=国家代码(US_01_120ms)
    "fetch": {
        "timeout": 10,  # 下载超时(秒)
        "workers": 10,  # 下载并发数(过大容易被源站封 IP)
        "retries": 2,   # 下载失败重试次数(0=不重试)
        "max_bytes": 0,  # 下载源最大字节数(字节, 0=不限制)
        "prefixes": [],  # 直连访问 GitHub 失败时的镜像前缀(默认不使用, 如 "https://ghfast.top/")
        "sources": [
            "https://cdn.jsdelivr.net/gh/seacdr/clash/output/alvin.txt",
            "https://cdn.jsdelivr.net/gh/seacdr/clash/output/top-all.txt",
            "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs/top100.txt",
            "https://cdn.jsdelivr.net/gh/rtwo2/FastNodes/sub/top.txt",
            "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia/BLACK_SS%2BAll_RUS.txt",
            "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia/BLACK_VLESS_RUS.txt",
            "https://cdn.jsdelivr.net/gh/awesome-vpn/awesome-vpn/sing-box.json",
            "https://cdn.jsdelivr.net/gh/barry-far/V2ray-config/Sub1.txt",
            "https://cdn.jsdelivr.net/gh/snakem982/proxypool/source/sing-box-2.json",
            "https://cdn.jsdelivr.net/gh/PuddinCat/BestClash/proxies.yaml",
            "https://cdn.jsdelivr.net/gh/shaoyouvip/free/all.yaml",
            "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions/output/singbox.json",
            "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers/sub",
        ],
    },
    "security": {
        # SS 无证书校验/服务端身份, 默认不收; 打开后仅收 AEAD / 2022 强加密且无插件的节点
        "allow_ss": False,
    },
    "delay": {
        # 每个 sing-box 进程承载的节点数；增大可减少进程启动次数，但会增加瞬时连接/内存
        "batch": 256,
        "timeout": 5,   # sing-box 请求超时(秒)
        "concurrency": 64,  # 每批延迟/国家检测并发请求数；AX6 建议 8-24
        "startup_timeout": 5,  # sing-box 启动超时(秒)
        "max_ms": 3000, # 延迟超过该值(毫秒)的节点丢弃, 0=不过滤
        "retries": 2,  # 失败后额外重试次数；多次成功时取最低延迟
        # 一次请求同时得到延迟+国家: 依次尝试, 首个成功响应的耗时即延迟
        "urls": [
            "http://www.cloudflare.com/cdn-cgi/trace",
            "http://ip-api.com/json?fields=status,countryCode",
        ],
    },
    "download": {
        "batch": 256,  # 每个 sing-box 进程承载的节点数；增大可减少进程启动次数，但会增加瞬时连接/内存
        "timeout": 5,  # 测速超时(秒)
        "concurrency": 8,  # 测速并发；AX6 可在 4-8 间调整，过高可能互相抢带宽
        "startup_timeout": 5,  # sing-box 启动超时(秒)
        "size": 2097152,  # 测速文件大小(字节), 2MiB
        "min_kbs": 100,  # 低于该速度(KB/s)丢弃, 0=不过滤
        "retries": 2,  # 失败后额外重试次数；多次成功时取最高下载速度
        "per_country": 0,  # 每国只测延迟最低的前 N 个, 0=不限
        "max_nodes": 0,  # 总上限, 0=不限
        "urls": [
            "https://speed.cloudflare.com/__down?bytes=2097152",
            "http://cachefly.cachefly.net/2mb.test",
        ],
    },
}


def deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config(path):
    over = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            over = json.load(f)
    else:
        print(f"[WARN] 配置文件不存在, 使用内置默认: {path}", file=sys.stderr)
    return deep_merge(DEFAULT_CONFIG, over)


# ════════════════════════════════════════════════════════════════════
# 日志: 只有"节点成功"才使用 INFO; 阶段进度用自定义 STAGE(25); 失败细节 DEBUG(-v)
# ════════════════════════════════════════════════════════════════════
STAGE = 25
logging.addLevelName(STAGE, "STAGE")
log = logging.getLogger("pipe")


def setup_log(verbose):
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%m-%d %H:%M:%S"))
    log.addHandler(h)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


# ════════════════════════════════════════════════════════════════════
# 通用小工具
# ════════════════════════════════════════════════════════════════════
def pmap(fn, items, workers):
    """有界线程池：网络 I/O 任务并发执行，线程数由 delay/download 各自配置。"""
    items = list(items)
    if not items:
        return
    q = queue.Queue()
    for it in items:
        q.put(it)
    count = max(1, min(int(workers), len(items)))

    def worker():
        while True:
            try:
                it = q.get_nowait()
            except queue.Empty:
                return
            try:
                fn(it)
            except Exception as e:  # 单个任务失败不影响整体
                log.debug("任务异常: %r", e)
            finally:
                q.task_done()

    ts = [threading.Thread(target=worker, daemon=True, name=f"net-test-{i + 1}") for i in range(count)]
    for t in ts:
        t.start()
    q.join()
    for t in ts:
        t.join()


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def is_ip(s):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except OSError:
            pass
    return False


def ip_ok(s):
    """公网可路由 IP; 排除私网/回环/CGNAT/fake-ip(198.18/15)/组播等。"""
    try:
        b = socket.inet_pton(socket.AF_INET, s)
    except OSError:
        try:
            b6 = socket.inet_pton(socket.AF_INET6, s)
        except OSError:
            return False
        return not (b6 in (b"\0" * 16, b"\0" * 15 + b"\x01") or b6[0] in (0xFC, 0xFD, 0xFF)
                    or (b6[0] == 0xFE and b6[1] & 0xC0 == 0x80))
    a, c = b[0], b[1]
    return not (a in (0, 10, 127) or a >= 224 or (a == 169 and c == 254) or (a == 172 and 16 <= c <= 31)
                or (a == 192 and c == 168) or (a == 198 and c in (18, 19)) or (a == 100 and 64 <= c <= 127))


def valid_host(h):
    if not h or re.search(r"[\s/@?#]", h):
        return False
    return ip_ok(h) if is_ip(h) else "." in h


def rss_mb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


_PROCS = set()


def _terminate(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    _PROCS.discard(p)


atexit.register(lambda: [_terminate(p) for p in list(_PROCS)])


class MemGuard:
    """内存软限制: 任务开始前若 本进程+sing-box 超过软限就等待/GC, 避免被 OOM 杀掉。"""

    def __init__(self, limit_mb=100):
        self.limit = limit_mb
        self.warned = False

    def used(self):
        return rss_mb(os.getpid()) + sum(rss_mb(p.pid) for p in list(_PROCS))

    def gate(self):
        for _ in range(100):
            if self.used() < self.limit * 0.9:
                return
            if not self.warned:
                self.warned = True
                log.warning("内存接近上限 %dMB, 暂缓新任务", self.limit)
            gc.collect()
            time.sleep(0.3)


GUARD = MemGuard()


def apply_mark(mark):
    """给本进程所有新 socket 打 SO_MARK(与 sing-box routing_mark 配套, 供主代理规则放行)。"""
    if not mark:
        return
    base = socket.socket

    class Marked(base):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            try:
                self.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
            except OSError:
                pass

    socket.socket = Marked


def write_atomic(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, path)


class Live:
    """实时落盘: 每个节点产生即写入并 flush。"""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.f = open(path, "w", encoding="utf-8")
        self.lock = threading.Lock()

    def add(self, line):
        with self.lock:
            self.f.write(line + "\n")
            self.f.flush()

    def close(self):
        self.f.close()


# ════════════════════════════════════════════════════════════════════
# 节点模型: 统一为 URI 风格 (proto, user, server, port, params)
# ════════════════════════════════════════════════════════════════════
PROTOS = ("vless", "vmess", "trojan", "hysteria2", "tuic", "anytls")
UDP_PROTOS = ("hysteria2", "tuic")
SCHEME = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "hysteria2": "hysteria2",
          "hy2": "hysteria2", "tuic": "tuic", "anytls": "anytls", "ss": "ss"}
TRANSPORTS = ("tcp", "ws", "grpc", "httpupgrade", "h2", "http")
SS_AEAD = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
TRUE = ("1", "true", "yes", "on")
_CANON = {k.lower(): k for k in ("serviceName", "allowInsecure", "headerType", "alterId")}
_ORD = {k: i for i, k in enumerate((
    "security", "encryption", "sni", "peer", "insecure", "allowInsecure", "type", "headerType", "host", "path",
    "serviceName", "mode", "fp", "alpn", "flow", "pbk", "sid", "spx", "obfs", "obfs-password", "mport",
    "congestion_control", "udp_relay_mode", "alterId", "scy", "plugin"))}


class Unsupported(Exception):
    pass


class Node:
    __slots__ = ("proto", "user", "server", "port", "p", "name", "cc", "ms", "mbps")

    def __init__(self, proto, user, server, port, p=None, name=""):
        self.proto, self.user, self.port = proto, user, int(port)
        self.server = str(server).strip().lower().rstrip(".")
        self.p = p if p is not None else {}
        self.name = name
        self.cc = self.ms = self.mbps = None

    def key(self):
        # p = self.p
        # 返回可比较的完整键，而不是先 hash 后比较，避免理论上的哈希碰撞导致误去重。
        # return (self.proto, self.user, self.server, self.port, (p.get("type") or "tcp").lower(),
        #         p.get("security", ""), p.get("sni", ""), p.get("host", ""), p.get("path", ""),
        #         p.get("serviceName", ""), p.get("flow", ""), p.get("pbk", ""), p.get("obfs-password", ""))

        # 按服务器协议 + 地址 + 端口去重：不区分账号、TLS/SNI、传输方式等参数。
        # 同一 server:port 只保留最先被 Collector 接收的一个节点。
        # server 在 __init__ 中已统一转为小写并去除末尾点号。
        return (self.proto, self.server, self.port)


def _canon(items):
    return {_CANON.get(k.lower(), k.lower()): v for k, v in items}


# ── 链接解析 ───────────────────────────────────────────────────────
def _split_hostport(hp):
    hp = hp.split("/", 1)[0]
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        ps = rest.lstrip(":")
    else:
        host, _, ps = hp.rpartition(":")
        if not host:
            raise ValueError("no port")
    m = re.match(r"(\d+)(.*)$", ps)
    if not m:
        raise ValueError("bad port")
    return unquote(host).strip().lower().rstrip("."), int(m.group(1)), (ps if m.group(2) else "")


def _parse_uri(scheme, rest):
    main, _, frag = rest.partition("#")
    main, _, query = main.partition("?")
    userinfo, at, hp = main.rpartition("@")
    if not at:
        return None
    host, port, extra = _split_hostport(hp)
    p = _canon(parse_qsl(query, keep_blank_values=True))
    if extra and scheme == "hysteria2":
        p["mport"] = extra
    return Node(scheme, unquote(userinfo), host, port, p, unquote(frag))


def _parse_ss(rest):
    main, _, frag = rest.partition("#")
    main, _, query = main.partition("?")
    if "@" in main:
        ui, _, hp = main.rpartition("@")
        ui = unquote(ui)
        if ":" not in ui:
            ui = b64d(ui).decode("utf-8")
    else:
        ui, _, hp = b64d(unquote(main)).decode("utf-8").rpartition("@")
    method, _, pw = ui.partition(":")
    host, port, _ = _split_hostport(hp)
    return Node("ss", f"{method}:{pw}", host, port, _canon(parse_qsl(query, keep_blank_values=True)), unquote(frag))


def _parse_vmess(rest):
    main, _, frag = rest.partition("#")
    d = json.loads(b64d(unquote(main)).decode("utf-8", "ignore"))
    net = d.get("net") or "tcp"
    p = {"type": net, "security": "tls" if str(d.get("tls", "")).lower() == "tls" else ""}
    for src in ("host", "sni", "alpn", "fp", "scy"):
        if d.get(src):
            p[src] = str(d[src])
    if d.get("path"):
        p["serviceName" if net == "grpc" else "path"] = str(d["path"])
    p["alterId"] = str(d.get("aid", 0))
    p["headerType"] = str(d.get("type") or "none")
    return Node("vmess", str(d["id"]), str(d["add"]), int(d["port"]), p, d.get("ps") or unquote(frag))


def parse_link(line):
    scheme, sep, rest = line.strip().strip("'\",").partition("://")
    scheme = SCHEME.get(scheme.lower()) if sep else None
    if not scheme:
        return None
    try:
        if scheme == "ss":
            return _parse_ss(rest)
        if scheme == "vmess" and "@" not in rest.split("#", 1)[0]:
            return _parse_vmess(rest)
        return _parse_uri(scheme, rest)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        return None


def _query(p):
    items = sorted(((k, v) for k, v in p.items() if v not in ("", None)), key=lambda kv: (_ORD.get(kv[0], 99), kv[0]))
    return "&".join(f'{k}={quote(str(v), safe="/,:@")}' for k, v in items)


def to_link(n, name):
    p = n.p
    host = f"[{n.server}]" if ":" in n.server else n.server
    if n.proto == "vmess":
        grpc = (p.get("type") == "grpc")
        d = {"v": "2", "ps": name, "add": n.server, "port": str(n.port), "id": n.user, "aid": p.get("alterId", "0"),
             "scy": p.get("scy", "auto"), "net": p.get("type", "tcp"), "type": p.get("headerType", "none"),
             "host": p.get("host", ""), "path": p.get("serviceName", "") if grpc else p.get("path", ""),
             "tls": "tls" if p.get("security") == "tls" else "", "sni": p.get("sni", ""),
             "alpn": p.get("alpn", ""), "fp": p.get("fp", "")}
        return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode()).decode()
    if n.proto == "ss":
        head = "ss://" + base64.urlsafe_b64encode(n.user.encode()).decode().rstrip("=") + f"@{host}:{n.port}"
    else:
        head = f'{n.proto}://{quote(n.user, safe=":")}@{host}:{n.port}'
    if n.proto in UDP_PROTOS:
        p = {k: v for k, v in p.items() if k not in ("security", "type", "headerType")}
    q = _query(p)
    return f"{head}{'?' + q if q else ''}#{quote(name, safe='')}"


# ── sing-box JSON / Clash YAML 对象 → Node ────────────────────────
_SB = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "hysteria2": "hysteria2", "tuic": "tuic",
       "anytls": "anytls", "shadowsocks": "ss"}


def _hostval(h):
    return ",".join(map(str, h)) if isinstance(h, list) else (str(h) if h else "")


def from_singbox(o):
    pr = _SB.get(o.get("type"))
    if not pr:
        return None
    tls, p = o.get("tls") or {}, {}
    rl = tls.get("reality") or {}
    if rl.get("enabled"):
        p.update(security="reality", pbk=rl.get("public_key", ""), sid=rl.get("short_id", ""))
    elif tls.get("enabled") and pr in ("vless", "vmess", "trojan", "anytls"):
        p["security"] = "tls"
    if tls.get("server_name"):
        p["sni"] = tls["server_name"]
    if tls.get("alpn"):
        p["alpn"] = _hostval(tls["alpn"])
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        p["fp"] = fp
    p["insecure"] = "1" if tls.get("insecure") else "0"
    tr = o.get("transport") or {}
    t = tr.get("type", "tcp")
    p["type"] = "h2" if t == "http" else t
    if tr.get("path"):
        p["path"] = tr["path"]
    h = _hostval(tr.get("host") or (tr.get("headers") or {}).get("Host"))
    if h:
        p["host"] = h
    if tr.get("service_name"):
        p["serviceName"] = tr["service_name"]
    if pr == "vless":
        user = o["uuid"]
        p["encryption"] = "none"
        if o.get("flow"):
            p["flow"] = o["flow"]
    elif pr == "vmess":
        user = o["uuid"]
        p.update(alterId=str(o.get("alter_id", 0)), scy=o.get("security", "auto"))
    elif pr == "tuic":
        user = f"{o['uuid']}:{o.get('password', '')}"
        p.update(congestion_control=o.get("congestion_control", ""), udp_relay_mode=o.get("udp_relay_mode", ""))
    elif pr == "ss":
        user = f"{o['method']}:{o['password']}"
        if o.get("plugin"):
            p["plugin"] = o["plugin"]
    else:
        user = o.get("password", "")
        if pr == "hysteria2":
            ob = o.get("obfs") or {}
            if ob.get("type"):
                p.update(obfs=ob["type"], **{"obfs-password": ob.get("password", "")})
            if o.get("server_ports"):
                p["mport"] = ",".join(str(x).replace(":", "-") for x in o["server_ports"])
    return Node(pr, str(user), o["server"], o["server_port"], p, o.get("tag", ""))


def from_clash(o):
    t = str(o.get("type", "")).lower()
    pr = {"hy2": "hysteria2"}.get(t, t)
    if pr not in PROTOS and pr != "ss":
        return None
    p = {}
    sni = o.get("servername") or o.get("sni") or o.get("peer")
    if sni:
        p["sni"] = str(sni)
    ro = o.get("reality-opts")
    if ro:
        p.update(security="reality", pbk=str(ro.get("public-key", "")), sid=str(ro.get("short-id", "")))
    elif o.get("tls") is True or pr in ("trojan", "anytls"):
        p["security"] = "tls"
    p["insecure"] = "1" if o.get("skip-cert-verify") else "0"
    if o.get("client-fingerprint"):
        p["fp"] = str(o["client-fingerprint"])
    if o.get("alpn"):
        p["alpn"] = _hostval(o["alpn"])
    net = str(o.get("network", "tcp")).lower()
    p["type"] = net
    ws, gr, h2 = o.get("ws-opts") or {}, o.get("grpc-opts") or {}, o.get("h2-opts") or o.get("http-opts") or {}
    hd = ws.get("headers") or {}
    if net == "ws":
        if ws.get("v2ray-http-upgrade"):
            p["type"] = "httpupgrade"
        p["path"] = str(ws.get("path", ""))
        p["host"] = str(hd.get("Host") or hd.get("host") or "")
    elif net == "grpc":
        p["serviceName"] = str(gr.get("grpc-service-name", ""))
    elif net in ("h2", "http"):
        p["type"] = "h2" if net == "h2" else "http"
        p["path"] = _hostval(h2.get("path"))
        p["host"] = _hostval(h2.get("host") or (h2.get("headers") or {}).get("Host"))
    if pr == "vless":
        user = o["uuid"]
        p["encryption"] = str(o.get("encryption") or "none")
        if o.get("flow"):
            p["flow"] = str(o["flow"])
    elif pr == "vmess":
        user = o["uuid"]
        p.update(alterId=str(o.get("alterId", 0)), scy=str(o.get("cipher", "auto")))
    elif pr == "tuic":
        user = f"{o['uuid']}:{o.get('password', '')}"
        p.update(congestion_control=str(o.get("congestion-controller", "")), udp_relay_mode=str(o.get("udp-relay-mode", "")))
    elif pr == "ss":
        user = f"{o['cipher']}:{o['password']}"
        if o.get("plugin"):
            p["plugin"] = str(o["plugin"])
    else:
        user = o.get("password") or o.get("auth") or ""
        if pr == "hysteria2":
            if o.get("obfs"):
                p.update(obfs=str(o["obfs"]), **{"obfs-password": str(o.get("obfs-password", ""))})
            if o.get("ports"):
                p["mport"] = str(o["ports"])
    return Node(pr, str(user), o["server"], o["port"], p, str(o.get("name", "")))


# ── 极简 YAML 子集解析(够用于 Clash proxies, 流式、低内存、无第三方依赖) ──
_KV = re.compile(r'^(?:"([^"]*)"|\'([^\']*)\'|([^\s\'"{\[#][^:]*?))\s*:(?:\s+(.*))?$')


def _ysc(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1].replace("''", "'") if s[0] == "'" else s[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("", "~", "null"):
        return None
    if re.fullmatch(r"-?(?:0|[1-9]\d*)", s):
        return int(s)
    return s


def _yflow(s, i=0):
    n = len(s)

    def ws(j):
        while j < n and s[j] in " \t":
            j += 1
        return j

    def val(j, stops):
        j = ws(j)
        if j >= n:
            return None, j
        if s[j] in "{[":
            return _yflow(s, j)
        if s[j] in "\"'":
            q, k = s[j], j + 1
            while k < n:
                if s[k] == "\\" and q == '"':
                    k += 2
                    continue
                if s[k] == q:
                    if q == "'" and k + 1 < n and s[k + 1] == "'":
                        k += 2
                        continue
                    break
                k += 1
            return _ysc(s[j:k + 1]), k + 1
        k = j
        while k < n and s[k] not in stops:
            k += 1
        return _ysc(s[j:k]), k

    i = ws(i)
    if s[i] == "{":
        d, i = {}, i + 1
        while True:
            i = ws(i)
            if i >= n or s[i] == "}":
                return d, i + 1
            if s[i] == ",":
                i += 1
                continue
            k, i = val(i, ":,}")
            i = ws(i)
            v = None
            if i < n and s[i] == ":":
                v, i = val(i + 1, ",}")
            d[str(k)] = v
    lst, i = [], i + 1
    while True:
        i = ws(i)
        if i >= n or s[i] == "]":
            return lst, i + 1
        if s[i] == ",":
            i += 1
            continue
        v, i = val(i, ",]")
        lst.append(v)


def _ykv(t):
    m = _KV.match(t)
    return None if not m else ((m.group(1) or m.group(2) or m.group(3) or "").strip(), (m.group(4) or "").strip())


def _is_item(t):
    return t == "-" or t.startswith("- ")


def _yblock(lines, i, ind):
    if _is_item(lines[i][1]):
        out = []
        while i < len(lines) and lines[i][0] == ind and _is_item(lines[i][1]):
            txt = lines[i][1]
            rest = txt[1:].strip()
            if not rest:
                i += 1
                if i < len(lines) and lines[i][0] > ind:
                    v, i = _yblock(lines, i, lines[i][0])
                else:
                    v = None
            elif rest[0] in "{[":
                v, i = _yflow(rest)[0], i + 1
            elif _ykv(rest):
                new_ind = ind + (len(txt) - len(txt[1:].lstrip()))
                lines[i] = (new_ind, rest)
                v, i = _yblock(lines, i, new_ind)
            else:
                v, i = _ysc(rest), i + 1
            out.append(v)
        return out, i
    d = {}
    while i < len(lines) and lines[i][0] >= ind:
        if lines[i][0] > ind or _is_item(lines[i][1]):
            if lines[i][0] == ind:
                break
            i += 1
            continue
        kv = _ykv(lines[i][1])
        i += 1
        if not kv:
            continue
        k, rest = kv
        if rest == "":
            if i < len(lines) and (lines[i][0] > ind or (lines[i][0] == ind and _is_item(lines[i][1]))):
                v, i = _yblock(lines, i, lines[i][0])
            else:
                v = None
        elif rest[0] in "{[":
            v = _yflow(rest)[0]
        else:
            v = _ysc(rest)
        d[k] = v
    return d, i


def iter_clash(text):
    raw = text.splitlines()
    start = next((i for i, l in enumerate(raw) if re.match(r"^\s*proxies\s*:\s*$", l)), None)
    if start is None:
        return
    base = len(raw[start]) - len(raw[start].lstrip())
    cur, item_ind = None, 0
    for l in raw[start + 1:]:
        t = l.strip()
        if not t or t.startswith("#"):
            continue
        ind = len(l) - len(l.lstrip())
        if ind < base or (ind == base and not _is_item(t)):
            break
        if _is_item(t) and (cur is None or ind <= item_ind):
            if cur:
                yield cur
            cur, item_ind = [(ind, t)], ind
        elif cur is not None:
            cur.append((ind, t))
    if cur:
        yield cur


# ── 订阅文本 → Node 迭代器 ──────────────────────────────────────────
def _from_obj(o):
    try:
        if isinstance(o, str):
            return parse_link(o)
        if isinstance(o, dict):
            return from_singbox(o) if "server_port" in o else from_clash(o)
    except (KeyError, ValueError, TypeError, AttributeError):
        pass
    return None


def parse_text(text):
    s = text.lstrip("\ufeff \t\r\n")
    if s[:1] in ("{", "["):
        try:
            data = json.loads(s)
        except ValueError:
            return
        del s
        if isinstance(data, dict):
            data = data.get("outbounds") or data.get("proxies") or []
        for o in data if isinstance(data, list) else []:
            yield _from_obj(o)
        return
    if re.search(r"^\s*proxies\s*:", s, re.M):
        for grp in iter_clash(s):
            try:
                v = _yblock(grp, 0, grp[0][0])[0][0]
            except (IndexError, KeyError, ValueError, TypeError):
                continue
            yield _from_obj(v)
        return
    if "://" not in s[:2000]:  # 整体 base64 订阅
        try:
            s = b64d(s).decode("utf-8", "ignore")
        except ValueError:
            return
    for line in s.splitlines():
        yield parse_link(line)


# ════════════════════════════════════════════════════════════════════
# 安全筛选: 强加密 + 强制证书校验 + 配置完整; 不满足一律剔除
#   (证书是否"有效"由后续 sing-box 测试时强制校验来最终裁决, 无效证书节点握手即失败)
# ════════════════════════════════════════════════════════════════════
def tls_mode(n):
    s = n.p.get("security", "").lower()
    if s == "reality":
        return "reality"
    if n.proto in ("hysteria2", "tuic", "anytls"):
        return "tls"
    if n.proto == "trojan":
        return "" if s == "none" else "tls"
    return "tls" if s in ("tls", "xtls") else ""


def _insecure(p):
    return any(str(p.get(k, "")).lower() in TRUE
               for k in ("insecure", "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"))


def check(n, allow_ss=False):
    """返回 None 表示通过, 否则返回拒绝原因。"""
    pr, p = n.proto, n.p
    if pr == "ss":
        if not allow_ss:
            return "ss"
    elif pr not in PROTOS:
        return "proto"
    if not (0 < n.port < 65536) or not valid_host(n.server):
        return "addr"
    if not n.user:
        return "auth"
    if pr == "ss":
        m = n.user.partition(":")[0].lower()
        return None if (m.startswith("2022-blake3-") or m in SS_AEAD) and not p.get("plugin") else "ss-weak"
    if pr in ("vless", "vmess", "tuic") and not UUID_RE.match(n.user.partition(":")[0]):
        return "uuid"
    mode = tls_mode(n)
    if not mode:
        return "no-tls"
    if _insecure(p):
        return "insecure"
    if mode == "reality":
        if not (p.get("pbk") and p.get("sni")):
            return "reality"
    elif not (p.get("sni") or p.get("peer") or not is_ip(n.server)):
        return "sni"
    if pr in ("vless", "vmess", "trojan"):
        if (p.get("type") or "tcp").lower() not in TRANSPORTS:
            return "transport"
        if p.get("headerType", "none") not in ("", "none"):
            return "obfs"
    if pr == "vless" and (p.get("encryption", "none") not in ("", "none")
                          or p.get("flow", "") not in ("", "xtls-rprx-vision")):
        return "vless-opt"
    if pr == "vmess" and (p.get("alterId", "0") not in ("", "0") or p.get("scy", "auto").lower() in ("none", "zero")):
        return "vmess-weak"
    if pr == "hysteria2" and p.get("obfs", "") not in ("", "salamander"):
        return "obfs"
    return None


def harden(n):
    """输出前显式写明强制校验证书, 与参考格式一致。"""
    p = n.p
    if n.proto in ("ss", "vmess"):
        return
    if tls_mode(n) == "tls":
        p["insecure"] = "0"
        if n.proto != "hysteria2":
            p["allowInsecure"] = "0"
        if n.proto in ("trojan", "anytls"):
            p["security"] = "tls"
    if n.proto in ("vless", "trojan", "anytls"):
        p.setdefault("type", "tcp")
        if p["type"] == "tcp":
            p.setdefault("headerType", "none")
    if n.proto == "vless":
        p.setdefault("encryption", "none")


# ════════════════════════════════════════════════════════════════════
# 节点 → sing-box outbound (不在 Python 中直连解析 DNS；域名交给 sing-box/系统解析)
# ════════════════════════════════════════════════════════════════════
def _tls(n, mode):
    p = n.p
    sni = p.get("sni") or p.get("peer") or ("" if is_ip(n.server) else n.server)
    t = {"enabled": True, "server_name": sni, "insecure": False}
    if p.get("alpn"):
        t["alpn"] = [a for a in re.split(r"[,;|]", p["alpn"]) if a]
    fp = p.get("fp", "")
    if mode == "reality":
        t["reality"] = {"enabled": True, "public_key": p["pbk"], "short_id": p.get("sid", "")}
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    elif fp and fp != "none" and n.proto not in UDP_PROTOS:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    return t


def _transport(p, host):
    t = (p.get("type") or "tcp").lower()
    path = p.get("path") or "/"
    if t == "tcp":
        return None
    if t == "ws":
        return {"type": "ws", "path": path, "headers": {"Host": host}}
    if t == "grpc":
        return {"type": "grpc", "service_name": p.get("serviceName") or p.get("path", "")}
    if t == "httpupgrade":
        return {"type": "httpupgrade", "path": path, "host": host}
    if t in ("h2", "http"):
        return {"type": "http", "path": path, "host": [h for h in host.split(",") if h]}
    raise Unsupported(t)


def to_outbound(n, ip, iso):
    p, pr = n.p, n.proto
    ob = {"type": "shadowsocks" if pr == "ss" else pr, "server": ip, "server_port": n.port}
    if pr == "ss":
        method, _, pw = n.user.partition(":")
        ob.update(method=method, password=pw)
    else:
        tls = _tls(n, tls_mode(n))
        host = p.get("host") or tls["server_name"] or n.server  # 用 IP 直连时必须保留原 Host/SNI
        if pr == "vless":
            ob.update(uuid=n.user, packet_encoding="xudp")
            if p.get("flow"):
                ob["flow"] = p["flow"]
        elif pr == "vmess":
            ob.update(uuid=n.user, security=p.get("scy") or "auto", alter_id=int(p.get("alterId") or 0))
        elif pr in ("trojan", "anytls"):
            ob["password"] = n.user
        elif pr == "hysteria2":
            ob["password"] = n.user
            tls.setdefault("alpn", ["h3"])
            if p.get("obfs"):
                ob["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password", "")}
            if p.get("mport"):
                ob["server_ports"] = [(x if re.search(r"[-:]", x) else f"{x}:{x}").replace("-", ":")
                                      for x in map(str.strip, p["mport"].split(",")) if x]
        elif pr == "tuic":
            uid, _, pw = n.user.partition(":")
            ob.update(uuid=uid, password=pw)
            tls.setdefault("alpn", ["h3"])
            if p.get("congestion_control"):
                ob["congestion_control"] = p["congestion_control"]
            udp = p.get("udp_relay_mode") or p.get("udp-relay-mode")
            if udp:
                ob["udp_relay_mode"] = udp
        ob["tls"] = tls
        if pr in ("vless", "vmess", "trojan"):
            tr = _transport(p, host)
            if tr:
                ob["transport"] = tr
    if iso.get("bind_interface"):
        ob["bind_interface"] = iso["bind_interface"]
    if iso.get("mark"):
        ob["routing_mark"] = int(iso["mark"])
    return ob


# ════════════════════════════════════════════════════════════════════
# 命名 / 读写
# ════════════════════════════════════════════════════════════════════
ZH = {"US": "美国", "JP": "日本", "HK": "香港", "TW": "台湾", "SG": "新加坡", "KR": "韩国", "DE": "德国",
      "GB": "英国", "FR": "法国", "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度",
      "TR": "土耳其", "BR": "巴西", "AR": "阿根廷", "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "FI": "芬兰",
      "PL": "波兰", "UA": "乌克兰", "CH": "瑞士", "AT": "奥地利", "IE": "爱尔兰", "IL": "以色列", "AE": "阿联酋",
      "MY": "马来西亚", "TH": "泰国", "VN": "越南", "ID": "印尼", "PH": "菲律宾", "CN": "中国", "MX": "墨西哥",
      "ZA": "南非", "NO": "挪威", "DK": "丹麦", "CZ": "捷克", "RO": "罗马尼亚", "BG": "保加利亚", "LT": "立陶宛",
      "LV": "拉脱维亚", "EE": "爱沙尼亚", "HU": "匈牙利", "PT": "葡萄牙", "BE": "比利时", "LU": "卢森堡",
      "IS": "冰岛", "KZ": "哈萨克斯坦", "CL": "智利", "CO": "哥伦比亚", "NZ": "新西兰", "SA": "沙特",
      "EG": "埃及", "PK": "巴基斯坦", "BD": "孟加拉", "KH": "柬埔寨", "MO": "澳门", "XX": "未知"}
_ZH_ON = [True]
_ZH_REV = {v: k for k, v in ZH.items()}


def label(cc):
    return ZH.get(cc, cc) if _ZH_ON[0] else cc


def mkname(n, seq, speed):
    s = f"{label(n.cc)}_{seq:02d}_{n.ms}ms"
    return s + (f"_{n.mbps:.2f}MB/s" if speed else "")


def assign_names(order, speed):
    seq, names = {}, {}
    for n in order:
        seq[n.cc] = seq.get(n.cc, 0) + 1
        names[id(n)] = mkname(n, seq[n.cc], speed)
    return names


def emit(path, order, speed):
    names = assign_names(order, speed)
    write_atomic(path, [to_link(n, names[id(n)]) for n in order])
    return names


_NAME_RE = re.compile(r"^(.+?)_(\d+)_(\d+)ms(?:_([\d.]+)MB/s)?$")


def read_nodes(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                n = parse_link(line)
                if not n:
                    continue
                m = _NAME_RE.match(n.name)
                if m:
                    n.cc, n.ms = _ZH_REV.get(m.group(1), m.group(1)), int(m.group(3))
                    n.mbps = float(m.group(4)) if m.group(4) else None
                out.append(n)
    except OSError as e:
        log.warning("读取失败 %s: %s", path, e)
    return out


# ════════════════════════════════════════════════════════════════════
# 网络: HTTP(直连抓取订阅) / HTTP(经本地 sing-box 测试节点)
# ════════════════════════════════════════════════════════════════════
def _ssl_ctx():
    try:
        return ssl.create_default_context() if ssl else None
    except Exception:
        return None


SSL_CTX = _ssl_ctx()


def make_opener(port=None):
    """port=None: 明确直连(禁用环境变量代理); 否则走本地测试 sing-box 的 HTTP 入站。"""
    px = {} if port is None else {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    hs = [urllib.request.ProxyHandler(px)]
    if SSL_CTX is not None:
        hs.append(urllib.request.HTTPSHandler(context=SSL_CTX))
    return urllib.request.build_opener(*hs)


def fetch_text(url, fc):
    """直连获取文本。retries 表示失败后额外重试次数；max_bytes=0 表示不设大小上限。"""
    op = make_opener(None)  # 禁用环境代理，始终直连。
    attempts = max(1, int(fc.get("retries", 0)) + 1)
    limit = max(0, int(fc.get("max_bytes", 0)))
    for u in [url] + [pre + url for pre in fc.get("prefixes", [])]:
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (X11; Linux) pipeline/1.1"})
                with op.open(req, timeout=fc["timeout"]) as r:
                    data = r.read(limit + 1) if limit else r.read()
                if limit and len(data) > limit:
                    log.warning("超过大小上限, 已截断: %s", u)
                    data = data[:limit]
                return data.decode("utf-8", "ignore")
            except Exception as e:
                log.debug("获取失败(第%d/%d次) %s: %s", attempt + 1, attempts, u, e)
                if attempt + 1 < attempts:
                    time.sleep(1)
    return None

# ════════════════════════════════════════════════════════════════════
# 测试基础设施: 多节点合并进单个 sing-box 进程
# ════════════════════════════════════════════════════════════════════
def free_ports(k):
    socks, ports = [], []
    for _ in range(k):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        socks.append(s)
    for s in socks:
        s.close()
    return ports


class Bench:
    def __init__(self, cfg):
        self.bin = cfg["paths"]["singbox"]
        self.tmp = cfg["paths"]["tmp"]
        self.iso = cfg["isolation"]
        self.mem = int(GUARD.limit)

    def run(self, nodes, task, workers, startup=10):
        pairs = []
        for n in nodes:
            try:
                pairs.append((n, to_outbound(n, n.server, self.iso)))
            except (Unsupported, KeyError, ValueError) as e:
                log.debug("不支持的节点 %s:%s (%r)", n.server, n.port, e)
        self._run(pairs, task, workers, startup)

    def _run(self, pairs, task, workers, startup):
        proc = ports = None
        while pairs:
            proc, ports, err = self._start(pairs, startup)
            if proc:
                break
            if len(pairs) == 1:
                log.debug("配置无效, 跳过 %s:%s: %s", pairs[0][0].server, pairs[0][0].port, err[-200:])
                return
            m = re.search(r"outbounds\[(\d+)\]", err)
            if m and int(m.group(1)) < len(pairs):  # sing-box 指出了问题节点: 剔除后重试
                del pairs[int(m.group(1))]
                continue
            mid = len(pairs) // 2  # 否则二分定位
            self._run(pairs[:mid], task, workers, startup)
            self._run(pairs[mid:], task, workers, startup)
            return
        if not proc:
            return
        try:
            pmap(lambda i: task(pairs[i][0], ports[i]), range(len(pairs)), workers)
        finally:
            _terminate(proc)
            for ext in (".json", ".err"):
                try:
                    os.remove(os.path.join(self.tmp, f"bench-{os.getpid()}{ext}"))
                except OSError:
                    pass

    def _start(self, pairs, startup):
        ports = free_ports(len(pairs))
        rules, inbounds = [], []
        for i, (_, ob) in enumerate(pairs):
            ob["tag"] = f"o{i}"
            inbounds.append({"type": "mixed", "tag": f"i{i}", "listen": "127.0.0.1", "listen_port": ports[i]})
            rules.append({"inbound": [f"i{i}"], "outbound": f"o{i}"})
        rules.append({"action": "reject"})  # 兜底: 绝不直连, 防止误测出"假成功"
        cfg = {"log": {"level": "error", "timestamp": False}, "inbounds": inbounds,
               "outbounds": [ob for _, ob in pairs], "route": {"rules": rules}}
        base = os.path.join(self.tmp, f"bench-{os.getpid()}")
        with open(base + ".json", "w") as f:
            json.dump(cfg, f)
        env = dict(os.environ, GOMEMLIMIT=f"{max(24, int(self.mem * 0.45))}MiB", GOGC="40", GOMAXPROCS="2")
        errf = open(base + ".err", "w+b")
        try:
            proc = subprocess.Popen([self.bin, "run", "-c", base + ".json"], stdout=subprocess.DEVNULL,
                                    stderr=errf, env=env, start_new_session=True)
        except OSError as e:
            errf.close()
            raise SystemExit(f"无法启动 sing-box: {e}")
        _PROCS.add(proc)
        t0 = time.time()
        while time.time() - t0 < startup:
            if proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", ports[-1]), 0.3).close()
                errf.close()
                return proc, ports, ""
            except OSError:
                time.sleep(0.15)
        _terminate(proc)
        errf.seek(0)
        err = errf.read().decode("utf-8", "ignore") or "startup timeout"
        errf.close()
        return None, None, err


def proxied_open(port, url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0", "Accept": "*/*"})
    return make_opener(port).open(req, timeout=timeout)


_CC = re.compile(r"(?:^|\n)loc=([A-Za-z]{2})\b")


def parse_cc(body):
    m = _CC.search(body)
    if m:
        return m.group(1).upper()
    try:
        d = json.loads(body)
    except ValueError:
        return None
    if isinstance(d, dict):
        for k in ("countryCode", "country_code", "country", "loc"):
            v = d.get(k)
            if isinstance(v, str) and len(v) == 2:
                return v.upper()
    return None


def make_delay_task(dc, on_ok):
    retries = max(0, int(dc.get("retries", 2)))

    def task(n, port):
        GUARD.gate()
        best_ms, best_cc = None, None
        # retries 是额外重试次数：默认最多测试 3 轮，最终取最低延迟。
        for _ in range(retries + 1):
            attempt_ms, attempt_cc = None, None
            for url in dc["urls"]:
                t0 = time.perf_counter()
                try:
                    with proxied_open(port, url, dc["timeout"]) as r:
                        body = r.read(8192).decode("utf-8", "ignore")
                except Exception:
                    continue
                ms = int((time.perf_counter() - t0) * 1000)
                cc = parse_cc(body)
                if attempt_ms is None or ms < attempt_ms:
                    attempt_ms, attempt_cc = ms, cc
                if cc:
                    break
            if attempt_ms is not None and (best_ms is None or attempt_ms < best_ms):
                best_ms, best_cc = attempt_ms, attempt_cc

        if best_ms is not None and (not dc["max_ms"] or best_ms <= dc["max_ms"]):
            on_ok(n, best_ms, best_cc or "XX")

    return task


def make_speed_task(dl, on_ok):
    size = dl["size"]
    retries = max(0, int(dl.get("retries", 2)))

    def task(n, port):
        GUARD.gate()
        best_mbps = None
        # retries 是额外重试次数：默认最多测试 3 轮，最终取最高下载速度。
        for _ in range(retries + 1):
            attempt_mbps = None
            for url in dl["urls"]:
                t0 = time.perf_counter()
                got = first_len = 0
                t1 = None
                try:
                    with proxied_open(port, url, dl["timeout"]) as r:
                        while True:
                            b = r.read1(65536)
                            if not b:
                                break
                            now = time.perf_counter()
                            if t1 is None:
                                t1, first_len = now, len(b)
                            got += len(b)
                            if got >= size or now - t0 > dl["timeout"]:
                                break
                except Exception:
                    pass
                if t1 is None or got - first_len <= 0 or got < 65536:
                    continue
                dt = max(time.perf_counter() - t1, 0.02)
                mbps = (got - first_len) / dt / 1048576.0
                attempt_mbps = mbps
                break  # 每轮使用第一个成功测速源；失败时才尝试下一个源

            if attempt_mbps is not None and (best_mbps is None or attempt_mbps > best_mbps):
                best_mbps = attempt_mbps

        if best_mbps is not None and best_mbps * 1024 >= dl["min_kbs"]:
            on_ok(n, best_mbps)

    return task


# ════════════════════════════════════════════════════════════════════
# 阶段 1: fetch — 抓取 + 安全筛选 + 去重, 实时写 top-fetch.txt
# ════════════════════════════════════════════════════════════════════
class Collector:
    def __init__(self, live, allow_ss):
        self.live, self.allow_ss = live, allow_ss
        self.seen, self.nodes, self.cnt, self.rej = set(), [], {}, {}
        self.lock = threading.Lock()

    def feed(self, it):
        total = secure = new = 0
        for n in it:
            if n is None:
                continue
            total += 1
            why = check(n, self.allow_ss)
            if why:
                with self.lock:
                    self.rej[why] = self.rej.get(why, 0) + 1
                continue
            secure += 1
            k = n.key()
            with self.lock:
                if k in self.seen:
                    continue
                self.seen.add(k)
                harden(n)
                c = self.cnt[n.proto] = self.cnt.get(n.proto, 0) + 1
                n.name = f"{n.proto}-{c:02d}"
                self.live.add(to_link(n, n.name))
                self.nodes.append(n)
                new += 1
        return total, secure, new


def stage_fetch(cfg, P):
    fc = cfg["fetch"]
    live = Live(P["fetch"])
    col = Collector(live, cfg["security"]["allow_ss"])
    t0 = time.time()

    def job(url):
        text = fetch_text(url, fc)
        if text is None:
            log.warning("✗ 获取失败: %s", url)
            return
        total, secure, new = col.feed(parse_text(text))
        del text
        log.log(STAGE, "获取 %s  节点=%d 安全=%d 新增=%d", url, total, secure, new)

    pmap(job, list(dict.fromkeys(fc["sources"])), fc["workers"])
    live.close()
    log.log(STAGE, "fetch 完成: 安全且去重 %d 个节点 (%.1fs); 剔除原因: %s", len(col.nodes), time.time() - t0,
            ", ".join(f"{k}={v}" for k, v in sorted(col.rej.items(), key=lambda x: -x[1])) or "无")
    gc.collect()
    return col.nodes


# ════════════════════════════════════════════════════════════════════
# 阶段 2: delay — 直接批量 sing-box 测试；一次请求同时得到延迟 + 出口国家
# 不做 Python 侧 DNS 直连预解析或 TCP 预探测，避免每个节点先探测、后代理测试。
# ════════════════════════════════════════════════════════════════════
def stage_delay(cfg, nodes, P):
    dc = cfg["delay"]
    cands = nodes
    log.log(STAGE, "跳过 DNS/TCP 预筛，直接代理测试 %d 个节点", len(cands))
    live, ok, seq, lock = Live(P["delay"]), [], {}, threading.Lock()

    def on_ok(n, ms, cc):
        with lock:
            n.cc, n.ms = cc, ms
            seq[cc] = seq.get(cc, 0) + 1
            name = mkname(n, seq[cc], False)
            live.add(to_link(n, name))
            ok.append(n)
        log.info("✓ 延迟 %s  %s://%s:%d", name, n.proto, n.server, n.port)

    task, bench, bs = make_delay_task(dc, on_ok), Bench(cfg), max(1, int(dc["batch"]))
    workers = max(1, min(int(dc.get("concurrency", 16)), bs))
    log.log(STAGE, "延迟检测并发=%d, batch=%d", workers, bs)
    for i in range(0, len(cands), bs):
        bench.run(cands[i:i + bs], task, workers, dc["startup_timeout"])
        log.log(STAGE, "延迟测试 %d/%d  可用 %d", min(i + bs, len(cands)), len(cands), len(ok))
    live.close()
    ok.sort(key=lambda n: n.ms)
    emit(P["delay"], ok, False)
    log.log(STAGE, "delay 完成: 可用 %d, 覆盖 %d 个国家/地区", len(ok), len({n.cc for n in ok}))
    return ok


# ════════════════════════════════════════════════════════════════════
# 阶段 3: download — 2MB 测速
# ════════════════════════════════════════════════════════════════════
def pick_candidates(nodes, per_country, max_nodes):
    """按延迟升序单次扫描：每地区最多取 K 个，再取全局前 max_nodes。

    排序 O(N log N)，扫描 O(N)；避免旧实现分组后再次排序。
    """
    ordered = sorted(nodes, key=lambda n: n.ms)
    if not per_country and not max_nodes:
        return ordered

    counts = {}
    out = []
    for n in ordered:
        if per_country:
            count = counts.get(n.cc, 0)
            if count >= per_country:
                continue
            counts[n.cc] = count + 1
        out.append(n)
        if max_nodes and len(out) >= max_nodes:
            break
    return out


def stage_download(cfg, nodes, P):
    dl = cfg["download"]
    cands = pick_candidates(nodes, dl["per_country"], dl["max_nodes"])
    log.log(STAGE, "测速候选 %d 个节点 (每国前 %s)", len(cands), dl["per_country"] or "∞")
    live, ok, seq, lock = Live(P["download"]), [], {}, threading.Lock()

    def on_ok(n, mbps):
        with lock:
            n.mbps = mbps
            seq[n.cc] = seq.get(n.cc, 0) + 1
            name = mkname(n, seq[n.cc], True)
            live.add(to_link(n, name))
            ok.append(n)
        log.info("✓ 测速 %s  %s://%s:%d", name, n.proto, n.server, n.port)

    task, bench, bs = make_speed_task(dl, on_ok), Bench(cfg), max(1, int(dl["batch"]))
    workers = max(1, min(int(dl["concurrency"]), bs))
    log.log(STAGE, "下载测速并发=%d, batch=%d, 单节点目标=%d bytes", workers, bs, dl["size"])
    for i in range(0, len(cands), bs):
        bench.run(cands[i:i + bs], task, workers, dl["startup_timeout"])
        log.log(STAGE, "测速 %d/%d  可用 %d", min(i + bs, len(cands)), len(cands), len(ok))
    live.close()
    ok.sort(key=lambda n: -n.mbps)
    emit(P["download"], ok, True)
    log.log(STAGE, "download 完成: 可用 %d", len(ok))
    return ok


# ════════════════════════════════════════════════════════════════════
# 阶段 4: output — 总榜 + 分国家榜 (原子写入; 空结果不覆盖旧文件)
# ════════════════════════════════════════════════════════════════════
def stage_output(cfg, nodes, P):
    if not nodes:
        log.warning("没有可输出的节点, 保留旧的输出文件不变")
        return nodes
    out = cfg["paths"]["out"]
    order = sorted(nodes, key=lambda n: (-(n.mbps or 0), n.ms or 0))
    names = assign_names(order, True)  # 同一节点在总榜/分国家榜中名称一致
    write_atomic(P["output"], [to_link(n, names[id(n)]) for n in order])
    written = {os.path.abspath(P["output"])}
    by = {}
    for n in order:
        by.setdefault(n.cc, []).append(n)
    for cc, lst in by.items():
        path = os.path.join(out, f"top-all-{label(cc)}.txt")
        write_atomic(path, [to_link(n, names[id(n)]) for n in lst])
        written.add(os.path.abspath(path))
        log.log(STAGE, "输出 top-all-%s.txt  %d 个 (最快 %.2fMB/s)", label(cc), len(lst), lst[0].mbps or 0)
    for f in glob.glob(os.path.join(out, "top-all-*.txt")):  # 清理已不存在的国家文件
        if os.path.abspath(f) not in written:
            try:
                os.remove(f)
            except OSError:
                pass
    log.log(STAGE, "output 完成: %s 共 %d 个节点, %d 个国家/地区", P["output"], len(order), len(by))
    return nodes


# ════════════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════════════
ALL_STAGES = ["fetch", "delay", "download", "output"]


def acquire_lock(path):
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            atexit.register(lambda: os.path.exists(path) and os.remove(path))
            return True
        except FileExistsError:
            try:
                with open(path) as f:
                    pid = int(f.read().strip() or 0)
            except (OSError, ValueError):
                pid = 0
            if pid and os.path.exists(f"/proc/{pid}"):
                return False
            try:
                os.remove(path)
            except OSError:
                pass
    return False


def refresh_delay_cache(cfg, path):
    """在跳过 delay 阶段时下载已由 GitHub Actions 筛选过的候选节点。空结果不会覆盖本地缓存。"""
    url = (cfg.get("paths") or {}).get("delay_cache_url", "").strip()
    if not url:
        return False
    text = fetch_text(url, cfg["fetch"])
    if not text:
        log.warning("远端延迟缓存获取失败: %s", url)
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    valid = sum(1 for node in parse_text(text) if node is not None)
    if valid == 0:
        log.warning("远端延迟缓存没有可解析节点，保留本地缓存: %s", url)
        return False
    write_atomic(path, lines)
    log.log(STAGE, "已载入 GitHub 延迟缓存: %d 个可解析节点", valid)
    return True


def run(args):
    cfg = load_config(args.config)
    setup_log(args.verbose)
    st = [s.strip() for s in args.stage.split(",") if s.strip()]
    bad = [s for s in st if s not in ALL_STAGES and s != "all"]
    if bad:
        log.error("未知阶段: %s (可选 all,%s)", ",".join(bad), ",".join(ALL_STAGES))
        return 2
    if "all" in st:
        # all 是完整流水线别名；与其他阶段并写仍然等价于全阶段。
        st = ALL_STAGES[:]
    else:
        st = [s for s in ALL_STAGES if s in st]
    if not st:
        log.error("至少指定一个阶段: all 或 %s", ",".join(ALL_STAGES))
        return 2

    tmp, out = cfg["paths"]["tmp"], cfg["paths"]["out"]
    os.makedirs(tmp, exist_ok=True)
    os.makedirs(out, exist_ok=True)
    P = {"fetch": os.path.join(tmp, "top-fetch.txt"), "delay": os.path.join(tmp, "top-delay.txt"),
         "download": os.path.join(tmp, "top-download.txt"), "output": os.path.join(out, "top-all.txt")}
    if not acquire_lock(os.path.join(tmp, "pipeline.lock")):
        log.warning("已有实例在运行, 本次退出")
        return 0

    _ZH_ON[0] = cfg["name_style"] == "zh"
    GUARD.limit = int(os.environ.get("MEM_LIMIT_MB") or cfg["limits"]["mem_mb"])
    try:
        threading.stack_size(256 * 1024)
    except (ValueError, RuntimeError):
        pass
    try:
        os.nice(int(cfg["limits"]["nice"]))
    except (OSError, AttributeError):
        pass
    apply_mark(int(cfg["isolation"].get("mark") or 0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # 走 finally/atexit, 确保回收 sing-box
    if ("delay" in st or "download" in st) and not shutil.which(cfg["paths"]["singbox"]):
        log.error("找不到 sing-box: %s", cfg["paths"]["singbox"])
        return 1

    funcs = {"fetch": lambda ns: stage_fetch(cfg, P), "delay": lambda ns: stage_delay(cfg, ns, P),
             "download": lambda ns: stage_download(cfg, ns, P), "output": lambda ns: stage_output(cfg, ns, P)}
    src = {"delay": P["fetch"], "download": P["delay"], "output": P["download"]}
    predecessor = {"delay": "fetch", "download": "delay", "output": "download"}
    nodes, last_stage, t0 = None, None, time.time()
    log.log(STAGE, "开始: 阶段=%s 内存上限=%dMB", ",".join(st), GUARD.limit)
    for s in st:
        if s == "fetch":
            nodes = funcs[s](None)
        else:
            if last_stage != predecessor[s]:
                if s == "download":
                    refresh_delay_cache(cfg, P["delay"])
                nodes = read_nodes(src[s])
                log.log(STAGE, "载入 %s: %d 个节点", src[s], len(nodes))
            if not nodes:
                if s == "output":
                    funcs[s]([])  # stage_output 会保留已有输出，不以空结果覆盖。
                else:
                    log.warning("阶段 %s 无输入节点，终止后续阶段", s)
                break
            nodes = funcs[s](nodes)
        last_stage = s
        gc.collect()
    log.log(STAGE, "全部完成, 总耗时 %.1fs, 当前内存估算 %.1fMB", time.time() - t0, GUARD.used())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pipeline.py", description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="执行流水线")
    r.add_argument("--stage", default="all", help="all 或逗号分隔: fetch,delay,download,output")
    r.add_argument("--config", default=os.path.join(HERE, "config.json"))
    r.add_argument("-v", "--verbose", action="store_true", help="输出 DEBUG 日志")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
