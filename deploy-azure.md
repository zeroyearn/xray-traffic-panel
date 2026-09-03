# Azure proxy-vm 部署分支

基于 main 的 xray 通用版，针对 Azure sing-box 代理 VM (IPv6-only) 的适配：

## 相对 main 的改动

| 文件 | 改动 |
|---|---|
| `scripts/panel_gen.py` | 当前连接统计：`xray` → `sing-box` 进程匹配 |
| `scripts/net_analyze.py` | tshark 增加 `ipv6.dst` 提取（IPv6 流量主力）；私有地址过滤加 v6 段 |
| `scripts/archive_append.py` | 同上（ipv6.dst） |
| `scripts/traffic-capture.service` | 排除端口 `80,443,8443,8080,22,2222`；ring buffer 20MB×72 |
| `svc_rules.json` | 新增：IP→服务映射库（与 argosbx 同版） |

## 目标机器现状 (proxy-vm, japaneast)

- sing-box VLESS-REALITY：80/443/8443，进程名 `sing-box`
- nginx :8080（订阅页），root `/var/www/html`
- 无公网 IPv4，面板经 IPv6 访问
- 无 xray access.log（`panel_gen` 会自动跳过该部分）

## 部署（新 token 示例：`TOKEN=<openssl rand -hex 8>`）

```bash
# 1. 依赖
DEBIAN_FRONTEND=noninteractive apt-get install -y tshark vnstat cron
systemctl enable --now cron vnstat

# 2. 拉分支包
curl -sL https://github.com/zeroyearn/xray-traffic-panel/archive/refs/heads/azure-proxy-vm.tar.gz | tar xz -C /tmp
mkdir -p /root/agsbx/panel /root/agsbx/pcap /var/www/html/$TOKEN
cp /tmp/xray-traffic-panel-azure-proxy-vm/scripts/*.py /tmp/xray-traffic-panel-azure-proxy-vm/scripts/*.sh /root/agsbx/panel/
cp /tmp/xray-traffic-panel-azure-proxy-vm/svc_rules.json /root/agsbx/panel/
cp /tmp/xray-traffic-panel-azure-proxy-vm/scripts/traffic-capture.service /etc/systemd/system/
cp /tmp/xray-traffic-panel-azure-proxy-vm/web/panel.html /var/www/html/$TOKEN/
chmod +x /root/agsbx/panel/*.sh
echo -n "$TOKEN" > /root/agsbx/panel/panel_token.log

# 3. 启动抓包 + 定时任务
systemctl daemon-reload && systemctl enable --now traffic-capture.service
cat >> /var/spool/cron/crontabs/root <<EOF
* * * * * XTP_AGSBX_DIR=/root/agsbx XTP_WEB_DIR=/var/www/html/$TOKEN XTP_INBOUND_PORTS=80,443,8443 python3 /root/agsbx/panel/panel_gen.py >> /root/agsbx/panel/panel.log 2>&1
*/2 * * * * XTP_PCAP_DIR=/root/agsbx/pcap XTP_NET_JSON=/var/www/html/$TOKEN/panel_net.json XTP_RULES=/root/agsbx/panel/svc_rules.json python3 /root/agsbx/panel/net_analyze.py >> /root/agsbx/panel/net_analyze.log 2>&1
*/5 * * * * XTP_PCAP_DIR=/root/agsbx/pcap XTP_ARCHIVE_DIR=/root/agsbx/panel/archive python3 /root/agsbx/panel/archive_append.py >> /root/agsbx/panel/archive_append.log 2>&1
* * * * * XTP_PCAP_DIR=/root/agsbx/pcap XTP_WEB_ROOT=/var/www/html XTP_AGSBX_DIR=/root/agsbx /root/agsbx/panel/health_check.sh
EOF

# 4. 面板地址
echo "http://[2603:1040:401::38]:8080/$TOKEN/panel.html"
```
