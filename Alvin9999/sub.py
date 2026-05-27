import requests, base64, urllib.parse, json, os
from bs4 import BeautifulSoup

b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()
b64e = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def decode_ssr(url):
    main, params = b64d(url[6:]).split("/?", 1)
    return main, {k: (b64d(v) if v else v) for kv in params.split("&") if kv for k, v in [kv.split("=", 1)]}

def encode_ssr(main, params):
    return "ssr://" + b64e(f"{main}/?{'&'.join(f'{k}={b64e(v)}' for k, v in params.items())}")

# 协议名直接取 :// 前的部分，n 为占位符（排序后统一编号，此处忽略）
HANDLERS = {
    "ssr":       lambda line, n: encode_ssr(*[(m := decode_ssr(line))[0], {**m[1], "remarks": f"ssr-{n:02d}"}]),
    "ss":        lambda line, n: f"{line.split('#')[0]}#{urllib.parse.quote(f'ss-{n:02d}')}",
    "vmess":     lambda line, n: "vmess://" + b64e(json.dumps({**json.loads(b64d(line[8:])), "ps": f"vmess-{n:02d}"}, ensure_ascii=False)),
    "vless":     lambda line, n: f"{line.split('#')[0]}#{urllib.parse.quote(f'vless-{n:02d}')}",
    "hysteria2": lambda line, n: f"{line.split('#')[0]}#{urllib.parse.quote(f'hysteria2-{n:02d}')}",
}

PROTOS = list(HANDLERS)  # 排序依据，也定义协议优先级

def fetch_and_process(urls, pre_tag="pre", output="Alvin9999/sub.txt"):
    # 第一遍：收集原始行，按协议分桶
    buckets = {p: [] for p in PROTOS}

    for url in urls:
        print(f"Fetching: {url}")
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        for pre in soup.find_all(pre_tag):
            for line in filter(None, (l.strip() for l in pre.get_text().splitlines())):
                proto = line.split("://")[0] if "://" in line else None
                if proto in buckets:
                    buckets[proto].append(line)

    # 第二遍：按协议顺序统一编号
    results = []
    for proto in PROTOS:
        for n, line in enumerate(buckets[proto], 1):
            results.append(HANDLERS[proto](line, n))

    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(results))

    sub64 = os.path.join(os.path.dirname(output), "sub64.txt")
    with open(sub64, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(results).encode()).decode())

    for p in PROTOS:
        print(f"  {p}: {len(buckets[p])}")
    print(f"共 {len(results)} 个节点 → {output} / {sub64}")


if __name__ == "__main__":
    fetch_and_process([
        "https://github.com/Alvin9999-newpac/fanqiang/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999-newpac/fanqiang/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999-newpac/fanqiang/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999-newpac/newpac/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999-newpac/newpac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999-newpac/newpac/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
    ])
