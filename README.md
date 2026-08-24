# Xray Traffic Panel

Xray 代理流量实时监控面板 + 长期域名流量归档。基于 `access.log`、`tcpdump` 抓包 SNI 分析、`vnstat` 与 `ss`,提供**按网址(域名)精确到字节**的流量统计。

> 从 xray 的 access log 只能看到"连了哪些域名";要看到**每个网址吃了多少流量**,需要对出站流量抓包并按 TLS SNI 归组。本项目用 tcpdump 常驻抓包 + tshark 提取 SNI,聚合出「域名 × 字节」数据,实时面板 + 永久归档两不误。

## 功能

- 📊 **实时 Web 面板**(纯静态 HTML,零后端依赖,30 秒自动刷新)
  - KPI:总连接数、今日流量(vnstat)、当前连接、近 15 分钟流量、来源 IP 数
  - 网址流量 TOP(近 15 分钟字节,SNI 归组)
  - 目标域名连接 TOP、来源 IP TOP、节点分布、小时活动柱状图、流量构成
- 🗄️ **长期归档**(每月几 MB,永久可查)
  - 每 5 分钟增量归档「域名 × 字节」到 JSONL(按日分文件,去重)
  - 命令行查询:单日 / 日期范围 / JSON 输出
- 🔍 access.log 解析:按域名/节点/来源 IP/小时统计连接数
- 🔄 全自动:cron 驱动采集,`@reboot` 自启,日志自动轮转

## 架构

```
                     ┌─────────────────────────────────────────────┐
                     │  tcpdump (常驻, 5min轮转 pcap, 保留6小时)     │
                     └──────────────┬──────────────────────────────┘
                                    │
              ┌─────────────────────┴─────────────────────┐
              │                                           │
   net_analyze.py (每2min)                    archive_append.py (每5min)
   滚动15min窗口 → panel_net.json              增量分析 → archive/domains_YYYYMMDD.jsonl
              │                                           │
              └──────────────┬────────────────────────────┘
                             ▼
                  panel_gen.py (每1min)
       access.log + vnstat + ss + panel_net.json
                             │
                             ▼
                  panel_data.json (静态JSON)
                             │
                             ▼
      busybox httpd / nginx / 任意静态服务器 → web/panel.html
```

## 安装

依赖(服务器上):

```bash
apt install -y tcpdump tshark vnstat
```

部署文件:

```bash
# 1. 脚本 (假设 xray 装在 /root/agsbx, web 根在 /root/websbx)
cp scripts/*.py scripts/*.sh /root/agsbx/panel/
cp web/panel.html /root/websbx/panel.html

# 2. 启动抓包 (会后台常驻)
/root/agsbx/panel/capture.sh
```

Cron 四项:

```cron
* * * * *     python3 /root/agsbx/panel/panel_gen.py
*/2 * * * *   python3 /root/agsbx/panel/net_analyze.py
*/5 * * * *   python3 /root/agsbx/panel/archive_append.py
@reboot       /root/agsbx/panel/capture.sh
```

(建议同时配置 `@reboot` 启动你的 httpd/nginx 与 xray access log 轮转:`scripts/rotate_access.sh` 每天 0 点轮转,保留 7 天)

## 使用

**面板:** 浏览器打开 `http://<服务器IP>:<端口>/panel.html`

**历史流量查询:**

```bash
python3 /root/agsbx/panel/archive_query.py                   # 今日
python3 /root/agsbx/panel/archive_query.py 20260824          # 指定日
python3 /root/agsbx/panel/archive_query.py 20260801 20260824 # 日期范围
python3 /root/agsbx/panel/archive_query.py 20260824 --json   # JSON 输出
```

**access.log 连接统计:**

```bash
python3 /root/agsbx/panel/domain_stats.py
```

## 配置

全部脚本支持环境变量覆盖(默认值适用于 `/root/agsbx` + `/root/websbx` 的 ArgoSBX 部署):

| 变量 | 默认 | 说明 |
|---|---|---|
| `XTP_AGSBX_DIR` | `/root/agsbx` | xray 安装目录(access.log 所在) |
| `XTP_WEB_DIR` | `/root/websbx` | Web 根目录(panel_data.json 输出) |
| `XTP_PCAP_DIR` | `/root/agsbx/pcap` | pcap 存放目录 |
| `XTP_ARCHIVE_DIR` | `/root/agsbx/panel/archive` | 长期归档目录 |
| `XTP_NET_JSON` | `<WEB_DIR>/panel_net.json` | 抓包分析输出 |
| `XTP_INBOUND_PORTS` | `52269,52459,10222` | 代理入站端口(面板"当前连接"按此区分) |
| `XTP_EXCLUDE_PORTS` | `52269,52459,10222,62153,22,7844` | 抓包排除端口(代理入站/SSH/HTTP 订阅/隧道) |
| `XTP_API_PORT` | `10085` | xray API 端口(日志轮转用) |
| `XTP_WINDOW_MIN` | `15` | 实时面板滚动窗口(分钟) |

## 目录

```
scripts/
  capture.sh          抓包守护(tcpdump, 5min 轮转)
  net_analyze.py      滚动窗口 SNI 分析 → panel_net.json
  panel_gen.py        汇总 access.log + vnstat + ss + net → panel_data.json
  archive_append.py   增量归档 pcap → JSONL(无重复计数)
  archive_query.py    长期归档查询
  domain_stats.py     access.log 域名/节点/来源统计
  rotate_access.sh    xray access.log 每日轮转(保留7天)
web/
  panel.html          实时面板(纯静态, fetch JSON 渲染)
```

## 说明与限制

- **SNI 归组**:HTTPS 流量按 TLS ClientHello 的 SNI(域名)归组;非 443 / 非 TLS 流量归到 `IP:<地址>`。TLS 1.3 ECH 或自定义协议无法识别时会落到 IP 分组。
- **字节口径**:`frame.len`(线缆字节),含 IP/TCP 头,比应用层字节略大。
- **xray stats API 兼容性**:Xray 26.x 的 `statsquery` 存在类型断言问题(返回 `QueryStats only works its own stats.Manager`),因此本项目不依赖 xray 内置统计,改用抓包,任何 xray/sing-box 版本都适用。
- **面板无鉴权**:公网暴露时建议加 HTTP Basic 或放在内网。
- **隐私**:抓包内容仅在本机分析(提取 SNI + 字节),原始 pcap 只保留 6 小时滚动窗口,不上传、不外传。

## License

MIT
