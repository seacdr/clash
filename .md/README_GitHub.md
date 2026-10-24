## Github节点订阅

- 在GitHub环境下，每6小时点自动运行；以下所有任务，实时打印出必要日志，节点成功才使用INFO。
- 1、获取给定的GitHub链接（.txt .json .yaml格式），获取链接+节点数；
- 2、快速筛选出安全节点+去重，注重加密与隐私，筛选出安全的节点（客户端严格校验相关参数，使用有效证书，正确配置的节点，并保持证书验证开启），使服务端不能解析请求，对客户端相对安全的节点。实时更新到`/tmp/sing-box/top-fetch.txt`；
- 3、在Github环境下，根据`top-fetch.txt`批量测试节点delay延迟+所属国家，命名节点：国家名称_序号_延迟，实时更新到`/tmp/sing-box/top-delay.txt`；所属国家根据API获取，不使用本地数据库。
- 4、3、在Github环境下，根据`top-delay.txt`批量测试节点下载5Mb网速，命名节点：国家名称_序号_延迟_测速，实时更新到`/tmp/sing-box/top-download.txt`；
- 5.1、最后整理`top-download.txt`，根据下载网速降序，命名节点：国家名称_序号_延迟_测速，实时更新到`/tmp/sing-box/top-all.txt`；
- 5.2、最后整理`top-download.txt`，根据国家名称+下载网速降序，命名节点：国家名称_序号_延迟_测速，实时更新到`/tmp/sing-box/top-all-<国家>.txt`；

### 本地环境依赖

- ubuntu-24.04, {"country":"United States","countryCode":"US","query":"4.242.196.131"}
- sing-box 1.12.25, python3 3.13.9

### 注意事项

- 输出格式.txt，每行一个节点，例如:anytls://dongtaiwang.com@ip5.934618.xyz:44889?security=tls&sni=ip5.934618.xyz&insecure=0&allowInsecure=0&type=tcp&headerType=none#anytls-01

```python
// 参考GitHub链接
{
  "fetch":{
    "timeout":20,
    "sources":[
        "https://raw.githubusercontent.com/seacdr/clash/refs/heads/master/output/alvin.txt",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
        "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/sing-box.json",
        "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
        "https://raw.githubusercontent.com/snakem982/proxypool/main/source/sing-box-2.json",
        "https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml",
        "https://raw.githubusercontent.com/shaoyouvip/free/refs/heads/main/all.yaml",
        "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/singbox.json",
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified_tls.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/anytls.txt"
      ]
  }
  "delay":{},
  "download":{},
}
```
- sources:[] 抓取的订阅地址列表
- delay:{} 批量测试延迟+所属国家等相关参数
- download:{} 批量测试连接+测速等相关参数

#### 用法: python3 pipeline.py run [--stage all,fetch,delay,download,output] [--config config.json] [-v]
- 阶段: fetch(抓取+安全筛选) → delay(延迟+国家) → download(5MB测速) → output(排序/分国家)

#### 用法: run.sh [run|install|uninstall|log]
- run        立即执行一次完整流水线(默认)；可附加参数，如: run.sh run [--stage all,fetch,delay,download,output] [--config config.json] [-v]
- install    安装依赖 + 写入 cron(每2小时整点)
- uninstall  移除 cron
- log        查看日志

### 时间效率优先

- 需求从两万节点，快速筛选出本地可用的节点。
- 优化整套逻辑，时间效率优先。哪些步骤非必要，可以省略/整合到一起，重新优化一下。 
- 请详细分析以上需求，合理完善的规划，在进行完整编码，实现所有功能。高集成+高代码质量。