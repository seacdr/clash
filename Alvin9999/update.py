import requests
from bs4 import BeautifulSoup
import base64
import urllib.parse
import json
import os

# --------- Base64 工具 ---------
def add_padding(data: str) -> str:
    return data + "=" * ((4 - len(data) % 4) % 4)

def base64_decode(data: str) -> str:
    return base64.urlsafe_b64decode(add_padding(data)).decode("utf-8")

def base64_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode("utf-8")).decode("utf-8").replace("=", "")

# --------- SSR 解码/编码 ---------
def decode_ssr(ssr_url: str):
    if ssr_url.startswith("ssr://"):
        ssr_url = ssr_url[6:]
    decoded = base64_decode(ssr_url)
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
    params = []
    for k, v in param_dict.items():
        v_encoded = base64_encode(v)
        params.append(f"{k}={v_encoded}")
    new_decoded = f"{main}/?{'&'.join(params)}"
    return "ssr://" + base64_encode(new_decoded)

# --------- 主处理函数 ---------
def fetch_and_process(counters, urls, pre_tag="pre"):
    results = []

    for url in urls:
        print(f"Fetching: {url}")
        resp = requests.get(url)
        resp.encoding = "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")
        pres = soup.find_all(pre_tag)

        for pre in pres:
            for line in pre.get_text().strip().splitlines():
                line = line.strip()
                if not line:
                    continue

                # ---- SSR ----
                if line.startswith("ssr://"):
                    main, params = decode_ssr(line)
                    counters["SSR"] += 1
                    new_name = f"SSR-{counters['SSR']:02d}"
                    params["remarks"] = new_name
                    results.append(encode_ssr(main, params))

                # ---- SS ----
                elif line.startswith("ss://"):
                    counters["SS"] += 1
                    new_name = f"SS-{counters['SS']:02d}"
                    base = line.split("#")[0]
                    results.append(base + "#" + urllib.parse.quote(new_name))

                # ---- VMESS ----
                elif line.startswith("vmess://"):
                    counters["VMESS"] += 1
                    new_name = f"VMESS-{counters['VMESS']:02d}"
                    cfg = base64_decode(line[8:])
                    j = json.loads(cfg)
                    j["ps"] = new_name
                    results.append("vmess://" + base64_encode(json.dumps(j, ensure_ascii=False)))

                # ---- VLESS ----
                elif line.startswith("vless://"):
                    counters["VLESS"] += 1
                    new_name = f"VLESS-{counters['VLESS']:02d}"
                    base = line.split("#")[0]
                    results.append(base + "#" + urllib.parse.quote(new_name))

                # ---- HYSTERIA2 ----
                elif line.startswith("hysteria2://"):
                    counters["HYSTERIA2"] += 1
                    new_name = f"HYSTERIA2-{counters['HYSTERIA2']:02d}"
                    base = line.split("#")[0]
                    results.append(base + "#" + urllib.parse.quote(new_name))

    # 保存结果
    os.makedirs("Alvin9999", exist_ok=True)
    with open("Alvin9999/update.md", "w", encoding="utf-8") as f:
        for link in results:
            f.write(link + "\n")

    print(f"已保存 {len(results)} 个节点到 Alvin9999/update.md")

# ---------------- 示例调用 ----------------
if __name__ == "__main__":
    counters = {"SS": 0, "SSR": 0, "VMESS": 0, "VLESS": 0, "HYSTERIA2": 0}
    urls = [
        "https://github.com/Alvin9999/new-pac/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999/new-pac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
        "https://github.com/Alvin9999/new-pac/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
    ]
    fetch_and_process(counters, urls, "pre")