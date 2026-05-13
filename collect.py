import requests
import base64
import json
import re
import socket
import dns.resolver
import time
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ================= 配置区域 =================

SOURCES = [
    # 域名源
    ("ProxyIP.KR.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("kr.william.us.ci", "DOMAIN"),
    ("proxy.xinyitang.dpdns.org", "DOMAIN"),
    ("jp.cle.us.ci", "DOMAIN"),
     ("sg.cle.us.ci", "DOMAIN"),

    # 订阅源
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "KR", "US"}
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
CF_ZONE_ID     = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "SG": os.getenv("CF_RECORD_SG"),
    "US": os.getenv("CF_RECORD_US"),
    "JP": os.getenv("CF_RECORD_JP"),
    "KR": os.getenv("CF_RECORD_KR"),
}

# 扩展到 10 个公共 DNS
PUBLIC_DNS = [
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "9.9.9.9",                       # Quad9
    "114.114.114.114", "114.114.115.115", # 114DNS
    "119.29.29.29",                  # DNSPod
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "v2rayNG/1.8.19",
    "ClashForAndroid/2.5.12",
]

# ================= 核心工具函数 =================

def log(msg):
    print(msg, flush=True)


def resolve_domain_extreme(domain):
    """
    极限解析：10个DNS × 5轮 + DoH + dig/nslookup
    彻底榨干负载均衡域名的所有 IP
    """
    ips = set()
    
    # 方法1：多 DNS 多轮查询
    resolver = dns.resolver.Resolver(configure=False)
    for round_num in range(5):
        for dns_server in PUBLIC_DNS:
            resolver.nameservers = [dns_server]
            resolver.timeout = 2
            resolver.lifetime = 3
            try:
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ips.add(rdata.address)
            except:
                pass
        time.sleep(0.1)  # 轮次间隔，获取不同轮询结果
    
    # 方法2：DNS over HTTPS (DoH) 绕过污染
    doh_urls = [
        f"https://dns.google/resolve?name={domain}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
        f"https://dns.quad9.net/dns-query?name={domain}&type=A",
    ]
    for doh_url in doh_urls:
        try:
            headers = {"accept": "application/dns-json"}
            resp = requests.get(doh_url, headers=headers, timeout=5)
            data = resp.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 1:
                    ip = answer.get("data", "")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        ips.add(ip)
        except:
            pass
    
    # 方法3：系统 dig 命令
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "A"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                ips.add(line)
    except:
        pass
    
    # 方法4：系统 nslookup 命令
    try:
        result = subprocess.run(
            ["nslookup", domain],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            match = re.search(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ips.add(match.group(1))
    except:
        pass
    
    # 方法5：兜底 socket
    if not ips:
        try:
            ips.add(socket.gethostbyname(domain))
        except:
            pass
    
    return ips


def safe_b64decode(data):
    """增强版 Base64 解码，处理各种异常格式"""
    if not data:
        return None
    
    # 清理非 Base64 字符
    data = data.strip()
    data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
    
    # 自动修复 padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="ignore")
        # 检查是否解码成功（应该包含协议头或可读文本）
        if any(proto in decoded for proto in ["://", "vmess", "vless", "trojan", "ss://"]):
            return decoded
        return decoded
    except:
        pass
    
    # 尝试 urlsafe 解码
    try:
        data_urlsafe = data.replace("+", "-").replace("/", "_")
        decoded = base64.urlsafe_b64decode(data_urlsafe + "==").decode("utf-8", errors="ignore")
        return decoded
    except:
        pass
    
    return None


def fetch_subscription_extreme(url):
    """
    极限订阅获取：多种方法 + 多种 UA + 重试
    """
    content = None
    
    # 方法1：curl（最强绕过能力）
    for ua in USER_AGENTS[:3]:
        try:
            cmd = [
                "curl", "-s", "-L",
                "-A", ua,
                "--compressed",
                "-H", "Accept: */*",
                "-H", "Accept-Language: en-US,en;q=0.9",
                "--max-time", "20",
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if result.returncode == 0 and result.stdout:
                if "Just a moment" not in result.stdout and len(result.stdout) > 50:
                    content = result.stdout
                    log(f"      [curl 成功] 获取到 {len(content)} 字符")
                    break
        except:
            pass
    
    # 方法2：wget
    if not content:
        for ua in USER_AGENTS[:2]:
            try:
                cmd = [
                    "wget", "-q", "-O", "-",
                    "-U", ua,
                    "--timeout=15",
                    url
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if result.returncode == 0 and result.stdout:
                    if "Just a moment" not in result.stdout and len(result.stdout) > 50:
                        content = result.stdout
                        log(f"      [wget 成功] 获取到 {len(content)} 字符")
                        break
            except:
                pass
    
    # 方法3：requests（带完整浏览器伪装）
    if not content:
        for ua in USER_AGENTS:
            try:
                headers = {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }
                resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
                if resp.status_code == 200 and "Just a moment" not in resp.text:
                    content = resp.text
                    log(f"      [requests 成功] 获取到 {len(content)} 字符")
                    break
            except:
                pass
    
    return content


def parse_node_link(line):
    """增强版节点解析，支持更多协议格式"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    # vmess://
    if line.startswith("vmess://"):
        try:
            b64_part = line[8:]
            decoded = safe_b64decode(b64_part)
            if not decoded:
                return None
            obj = json.loads(decoded)
            host = obj.get("add", "")
            port = str(obj.get("port", "443"))
            if host:
                return host, port
        except:
            pass
        return None
    
    # vless:// trojan:// hysteria2:// hy2:// ss://
    if "://" in line:
        try:
            # 去掉 # 后面的备注
            body = line.split("#")[0] if "#" in line else line
            
            # 提取协议后部分
            after_proto = body.split("://", 1)[1]
            
            # 去掉 userinfo (uuid@, password@, etc.)
            if "@" in after_proto:
                after_proto = after_proto.rsplit("@", 1)[1]
            
            # 取 host:port 部分
            host_port = after_proto.split("/")[0].split("?")[0]
            
            # 处理 IPv6 格式 [::1]:port
            if host_port.startswith("["):
                return None  # 暂不处理 IPv6
            
            if ":" in host_port:
                host, port = host_port.split(":", 1)
            else:
                host, port = host_port, "443"
            
            if host:
                return host, port
        except:
            pass
        return None
    
    # 纯 IP 或域名格式：1.2.3.4:443 或 domain.com:443
    match = re.match(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]|\d+\.\d+\.\d+\.\d+)(?::(\d+))?', line)
    if match:
        return match.group(1), match.group(2) or "443"
    
    return None


def check_node(ip, port):
    """检测节点真实地区"""
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=15
        ).json()
        if resp.get("success") is True:
            region = (
                resp.get("probe_results", {})
                .get("ipv4", {})
                .get("exit", {})
                .get("country", "UN")
                .upper()
            )
            return region
    except:
        pass
    return "UN"


def tcp_latency(ip, port):
    """TCP 延迟测试"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, int(port)))
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999


def update_cloudflare_dns(region, ips):
    """更新 Cloudflare DNS"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not ips:
        return

    record_name = CUSTOM_DOMAIN_MAP.get(region)
    if not record_name:
        if CF_BASE_DOMAIN:
            record_name = f"{region.lower()}.{CF_BASE_DOMAIN}"
        else:
            return

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    log(f"      [CF] 更新 {record_name} -> {ips}")
    
    try:
        # 删除旧记录
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=10).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=10)
        
        # 添加新记录
        for ip in ips:
            data = {"type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False}
            requests.post(base_url, headers=headers, json=data, timeout=10)
    except Exception as e:
        log(f"      [!] DNS 更新异常: {e}")


# ================= 主流程 =================

def main():
    log("=" * 70)
    log("🚀 [极限节点提取与分区测速工具 v4.0] 开始运行")
    log("=" * 70 + "\n")

    domain_raw_nodes = set()
    sub_raw_nodes = set()

    # ============ 阶段 1：极限提取 ============
    log("📡 [阶段一] 极限解析所有数据源...\n")

    for src, typ in SOURCES:
        if typ == "DOMAIN":
            log(f"🌐 [域名源] {src}")
            ips = resolve_domain_extreme(src)
            log(f"   ↳ 共解析出 {len(ips)} 个 IP:")
            for ip in sorted(ips):
                log(f"      • {ip}")
                domain_raw_nodes.add((ip, "443"))
            log("")

        elif typ == "SUB":
            log(f"📥 [订阅源] {src[:65]}...")
            content = fetch_subscription_extreme(src)
            
            if not content:
                log("   ↳ ⚠️ 获取失败，跳过")
                continue
            
            # 解码
            decoded = safe_b64decode(content)
            if decoded:
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
                log(f"   ↳ Base64 解码成功，共 {len(lines)} 行")
            else:
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                log(f"   ↳ 非 Base64 内容，共 {len(lines)} 行")
            
            # 逐行解析
            extracted_count = 0
            for line in lines:
                parsed = parse_node_link(line)
                if not parsed:
                    continue
                
                host, port = parsed
                
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                    log(f"      • 直接 IP: {host}:{port}")
                    sub_raw_nodes.add((host, port))
                    extracted_count += 1
                else:
                    # 域名需要解析
                    ips = resolve_domain_extreme(host)
                    for ip in ips:
                        log(f"      • 域名 {host} -> {ip}:{port}")
                        sub_raw_nodes.add((ip, port))
                        extracted_count += 1
            
            log(f"   ↳ 本订阅共提取 {extracted_count} 个 IP 节点\n")

    log("-" * 70)
    log(f"📊 采集汇总: 域名源 {len(domain_raw_nodes)} 个，订阅源 {len(sub_raw_nodes)} 个")
    log("-" * 70 + "\n")

    # ============ 阶段 2：并发检测 ============
    log("🔍 [阶段二] 开始 API 地区检测与 TCP 延迟测试...\n")

    domain_verified = defaultdict(list)
    sub_verified = defaultdict(list)

    def process_task(ip, port, source_type):
        region = check_node(ip, port)
        if region in ALLOWED_REGIONS:
            latency = tcp_latency(ip, port)
            if latency < 2000:
                return ip, port, region, latency, source_type
        return None

    all_tasks = [(ip, port, "DOMAIN") for ip, port in domain_raw_nodes] + \
                [(ip, port, "SUB") for ip, port in sub_raw_nodes]

    completed = 0
    total = len(all_tasks)

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(process_task, ip, port, st): (ip, port, st)
            for ip, port, st in all_tasks
        }
        
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            
            if res:
                ip, port, region, latency, st = res
                log(f"   [{completed}/{total}] ✅ {ip}:{port} | {region} | {latency}ms | {st}")
                if st == "DOMAIN":
                    domain_verified[region].append((ip, port, latency))
                else:
                    sub_verified[region].append((ip, port, latency))
            elif completed % 50 == 0:
                log(f"   [{completed}/{total}] 检测中...")

    # ============ 阶段 3：按地区分组输出 ============
    log("\n💾 [阶段三] 按【各地区分别取前 5】规则输出...\n")

    domain_output_lines = []
    sub_output_lines = []

    for region in sorted(ALLOWED_REGIONS):
        log(f"🌍 地区: {region}")
        
        # 域名源处理
        domain_pool = domain_verified.get(region, [])
        domain_top5 = sorted(domain_pool, key=lambda x: x[2])[:TOP_N]
        log(f"   [域名源] 存活 {len(domain_pool)} 个，选出前 {len(domain_top5)} 个")
        
        if domain_top5:
            ips = [n[0] for n in domain_top5]
            update_cloudflare_dns(region, ips)
            for ip, port, lat in domain_top5:
                domain_output_lines.append(f"{ip}#{region}")
                log(f"      → {ip} ({lat}ms)")
        
        # 订阅源处理
        sub_pool = sub_verified.get(region, [])
        sub_top5 = sorted(sub_pool, key=lambda x: x[2])[:TOP_N]
        log(f"   [订阅源] 存活 {len(sub_pool)} 个，选出前 {len(sub_top5)} 个")
        
        if sub_top5:
            for ip, port, lat in sub_top5:
                sub_output_lines.append(f"{ip}:{port}#{region}")
                log(f"      → {ip}:{port} ({lat}ms)")
        
        log("")

    # 写入文件
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(domain_output_lines))
    
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sub_output_lines))

    log("=" * 70)
    log("🎉 任务完成！")
    log(f"   ✅ domain_ips.txt: {len(domain_output_lines)} 行")
    log(f"   ✅ other_ips.txt: {len(sub_output_lines)} 行")
    log("=" * 70)


if __name__ == "__main__":
    main()
