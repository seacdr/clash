import os
import requests
from bs4 import BeautifulSoup

# 配置信息
filepath='Alvin9999/update.md'
ssr_url='https://github.com/Alvin9999/new-pac/wiki/ss%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7'
v2ray_url='https://github.com/Alvin9999/new-pac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7'
goflyway_url='https://github.com/Alvin9999/new-pac/wiki/Goflyway%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7'

# 通过URL获取配置
def get_con(url,proxcon,filepath):
    print(url)
    print(filepath)
    # 发送HTTP请求
    response = requests.get(url)
    # 检查请求是否成功
    if response.status_code == 200:
        # 解析网页内容
        soup = BeautifulSoup(response.text, 'html.parser')
        # 查找包含特定文本的元素
        pre_tags = soup.find_all('pre')  # 在网页中，vmess链接通常会在 <pre> 标签内
        # 打开文件用于写入
        filepath_wa='w'
        if os.path.exists(filepath):
            filepath_wa='a'
        with open(filepath, filepath_wa) as file:
            for pre in pre_tags:
                #if 'vmess://' in pre.get_text():
                #print(pre.get_text())
                if proxcon in pre.get_text():
                    link = pre.get_text().strip()
                    # 写入文件
                    file.write(link + '\n')
                    print('Found and wrote link:\n', link)         
    else:
        print('请求失败，状态码：', response.status_code)

# 主程序
if __name__ == "__main__":
    print("注意，可能需要vpn，可运行vpn工具后开启系统代理！")
    # ##获取ss配置
    get_con(ssr_url, 'ss://', filepath)
    # ##获取ssr配置
    get_con(ssr_url, 'ssr://', filepath)
    # ##获取v-ray配置
    get_con(v2ray_url, 'vmess://', filepath)
    get_con(v2ray_url, 'vless://', filepath)
    # ##获取goflyway配置
    # get_con(goflyway_url, 'goflyway', filepath)
