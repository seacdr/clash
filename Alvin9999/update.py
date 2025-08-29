import os
import requests
from bs4 import BeautifulSoup

# 统一配置：只需要维护 url 列表
urls = [
    "https://github.com/Alvin9999/new-pac/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
    "https://github.com/Alvin9999/new-pac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
    "https://github.com/Alvin9999/new-pac/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7",
]

# 常见协议前缀
protocols = ["ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria2://", "goflyway"]

# 协议计数器
counters = {p.upper().replace("://", ""): 0 for p in protocols}


def fetch_nodes(url):
    """
    爬取网页，获取 <pre> 标签内的所有节点
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"请求失败：{url} 状态码 {response.status_code}")
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        pre_tags = soup.find_all("pre")

        nodes = []
        for pre in pre_tags:
            lines = pre.get_text().strip().splitlines()
            for line in lines:
                line = line.strip()
                for proto in protocols:
                    if line.startswith(proto):
                        nodes.append(line)
        return nodes
    except Exception as e:
        print(f"获取失败：{url} 错误：{e}")
        return []


def save_nodes(filepath, all_nodes):
    """
    按协议类型编号后写入文件
    """
    with open(filepath, "w", encoding="utf-8") as f:
        for node in all_nodes:
            # 自动识别协议
            proto = next((p for p in protocols if node.startswith(p)), None)
            if not proto:
                continue

            proto_name = proto.upper().replace("://", "")
            counters[proto_name] += 1
            node_name = f"{proto_name}-{counters[proto_name]:02d}"

            f.write(f"{node_name}: {node}\n")
            print(f"写入 {node_name}")


if __name__ == "__main__":
    print("注意，可能需要VPN，可运行VPN工具后开启系统代理！")

    all_nodes = []
    for url in urls:
        all_nodes.extend(fetch_nodes(url))

    save_nodes("Alvin9999/update.md", all_nodes)

    print("\n完成！结果已保存到 Alvin9999/update.md")
