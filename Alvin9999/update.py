import requests
from bs4 import BeautifulSoup
import base64
import urllib.parse
import json
import os


# --------- Base64 工具 ---------
def add_padding(data: str) -> str:
    """补全 Base64 编码的等号"""
    return data + "=" * ((4 - len(data) % 4) % 4)


def base64_decode(data: str) -> str:
    """Base64 解码"""
    return base64.urlsafe_b64decode(add_padding(data)).decode("utf-8")


def base64_encode(data: str) -> str:
    """Base64 编码并去掉等号"""
    return base64.urlsafe_b64encode(data.encode("utf-8")).decode("utf-8").rstrip("=")


# --------- SSR 解码/编码 ---------
def decode_ssr(ssr_url: str):
    """解析 SSR 链接"""
    ssr_body = ssr_url[6:] if ssr_url.startswith("ssr://") else ssr_url
    decoded = base64_decode(ssr_body)
    main, params = decoded.split("/?", 1)

    param_dict = {}
    for kv in params.split("&"):
        if kv:
            k, v = kv.split("=", 1)
            try:
                v = base64_decode(v)
            except Exception:
                v = urllib.parse.unquote(v)
            param_dict[k] = v
    return main, param_dict


def encode_ssr(main: str, param_dict: dict) -> str:
    """重新生成 SSR 链接"""
    params = [f"{k}={base64_encode(v)}" for k, v in param_dict.items()]
    new_decoded = f"{main}/?{'&'.join(params)}"
    return "ssr://" + base64_encode(new_decoded)


# --------- 主处理函数 ---------
def fetch_and_process(counters: dict, urls: list, pre_tag="pre", output="Alvin9999/update.md"):
    results = []

    for url in urls:
        print(f"Fetching: {url}")
        resp = requests.get(url)
        resp.encoding = "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")

        for pre in soup.find_all(pre_tag):
            for line in pre.get_text().strip().splitlines():
                line = line.strip()
                if not line:
                    continue

                # ---- SSR ----
                if line.startswith("ssr://"):
                    main, params = decode_ssr(line)
                    counters["SSR"] += 1
                    params["remarks"] = f"SSR-{counters['SSR']:02d}"
                    results.append(encode_ssr(main, params))

                # ---- SS ----
                elif line.startswith("ss://"):
                    counters["SS"] += 1
                    base = line.split("#")[0]
                    results.append(f"{base}#{urllib.parse.quote(f'SS-{counters['SS']:02d}')}")

                # ---- VMESS ----
                elif line.startswith("vmess://"):
                    counters["VMESS"] += 1
                    cfg = json.loads(base64_decode(line[8:]))
                    cfg["ps"] = f"VMESS-{counters['VMESS']:02d}"
                    results.append("vmess://" + base64_encode(json.dumps(cfg, ensure_ascii=False)))

                # ---- VLESS ----
                elif line.startswith("vless://"):
                    counters["VLESS"] += 1
                    base = line.split("#")[0]
                    results.append(f"{base}#{urllib.parse.quote(f'VLESS-{counters['VLESS']:02d}')}")

                # ---- HYSTERIA2 ----
                elif line.startswith("hysteria2://"):
                    counters["HYSTERIA2"] += 1
                    base = line.split("#")[0]
                    results.append(f"{base}#{urllib.parse.quote(f'HYSTERIA2-{counters['HYSTERIA2']:02d}')}")
                    
    #倒序：最新抓取/处理的节点放在最前面
    results.reverse()
    # 保存结果
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(results))
    print(f"已保存 {len(results)} 个节点到 {output}")


# ---------------- 示例调用 ----------------
if __name__ == "__main__":
    counters = {"SS": 0, "SSR": 0, "VMESS": 0, "VLESS": 0, "HYSTERIA2": 0}
    urls = [
        "https://github.com/Alvin9999/new-pac/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999/new-pac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999/new-pac/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
    ]
    fetch_and_process(counters, urls)
