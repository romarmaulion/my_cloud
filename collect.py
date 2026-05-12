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
    # 域名源（类型为 DOMAIN）
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("proxy.xinyitang.dpdns.org", "DOMAIN"),

    # 订阅源（类型为 SUB）
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5  # 每个地区挑选的最优节点数量
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
CF_ZONE_ID     = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

# 各地区独立更新的域名记录
CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "SG": os.getenv("CF_RECORD_SG"),
    "US": os.getenv("CF_RECORD_US"),
    "JP": os.getenv("CF_RECORD_JP"),
    "TW": os.getenv("CF_RECORD_TW"),
}

PUBLIC_DNS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "114.114.114.114", "9.9.9.9"]

# ================= 核心工具函数 =================

def log(msg):
    print(msg, flush=True)

def resolve_maximal(domain):
    """榨干解析：多次查询多个DNS，获取所有负载均衡IP"""
    ips = set()
    resolver = dns.resolver.Resolver(configure=False)
    
    for _ in range(3):
        for dns_server in PUBLIC_DNS:
            resolver.nameservers = [dns_server]
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.cache = None
            try:
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ips.add(rdata.address)
            except:
                pass

    if not ips:
        try:
            ips.add(socket.gethostbyname(domain))
        except:
            pass

    return ips

def safe_b64decode(data):
    """安全解码 Base64"""
    if not data: return None
    try:
        data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None

def fetch_content_bypass_cf(url):
    """强力绕过 Cloudflare 获取内容"""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    try:
        cmd = ["curl", "-s", "-L", "-A", ua, "--compressed", "--max-time", "15", url]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and "Just a moment" not in res.stdout:
            return res.stdout
    except: pass

    try:
        resp = requests.get(url, headers={"User-Agent": ua}, timeout=15)
        if "Just a moment" not in resp.text:
            return resp.text
    except: pass
    return None

def parse_node_link(line):
    """解析节点链接为 host, port"""
    line = line.strip()
    if not line or line.startswith("#"): return None

    if line.startswith("vmess://"):
        decoded = safe_b64decode(line[8:])
        if not decoded: return None
        try:
            v2 = json.loads(decoded)
            return v2.get("add", ""), str(v2.get("port", "443"))
        except: return None

    if "://" in line:
        body = line.split("://", 1)[1]
        if "#" in body: body = body.rsplit("#", 1)[0]
        if "@" in body: body = body.rsplit("@", 1)[1]
        host_port = body.split("/")[0].split("?")[0]
        if host_port.startswith("["): return None 
        return host_port.split(":", 1) if ":" in host_port else (host_port, "443")

    match = re.match(r'^([a-zA-Z0-9.-]+)(?::(\d+))?', line.split("#")[0])
    if match: return match.group(1), match.group(2) or "443"
    return None

def check_node(ip, port):
    """调用 API 判断节点的真实落地地区"""
    try:
        resp = requests.get(CHECK_API, params={"proxyip": f"{ip}:{port}"}, timeout=15).json()
        if resp.get("success") is True:
            return resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
    except: pass
    return "UN"

def tcp_latency(ip, port):
    """测试真实的 TCP 握手延迟"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, int(port)))
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999

def update_cloudflare_dns(region, ips):
    """针对单个地区，将该地区的 IP 推送到该地区绑定的域名"""
    if not CF_API_TOKEN or not CF_ZONE_ID: return

    # 优先使用 CUSTOM_DOMAIN_MAP 里为各地区独立配置的域名（如 hk.yourdomain.com）
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

    log(f"      [CF API] 开始将 {region} 地区的 {len(ips)} 个精选 IP 覆写至域名: {record_name}")
    try:
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers)

        for ip in ips:
            data = {"type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False}
            requests.post(base_url, headers=headers, json=data)
            log(f"      [CF API] -> 添加 A 记录: {ip}")
    except Exception as e:
        log(f"      [!] DNS 更新异常: {e}")

# ================= 主控制流 =================

def main():
    log("="*65)
    log("🚀 [节点精准提取与分区测速工具] 开始运行")
    log("="*65 + "\n")

    domain_raw_nodes = set()
    sub_raw_nodes = set()

    # ---------------- 阶段 1：极致提取 ----------------
    log("📡 [阶段一] 开始深入解析节点池 (所有提取的 IP 都将打印)...\n")

    for src, typ in SOURCES:
        if typ == "DOMAIN":
            log(f"🌐 [解析域名源] {src}")
            ips = resolve_maximal(src)
            for ip in ips:
                log(f"   ↳ 提取 IP: {ip}")
                domain_raw_nodes.add((ip, "443"))

        elif typ == "SUB":
            log(f"\n📥 [解析订阅源] {src[:65]}...")
            content = fetch_content_bypass_cf(src)
            if not content: continue

            decoded = safe_b64decode(content)
            lines = decoded.splitlines() if decoded else content.splitlines()

            for line in lines:
                parsed = parse_node_link(line)
                if not parsed: continue
                host, port = parsed
                
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                    log(f"   ↳ 提取订阅直连 IP: {host}:{port}")
                    sub_raw_nodes.add((host, port))
                else:
                    ips = resolve_maximal(host)
                    for ip in ips:
                        log(f"   ↳ 订阅内域名转换 -> IP: {ip}:{port}")
                        sub_raw_nodes.add((ip, port))
    log("\n" + "-"*65)

    # ---------------- 阶段 2：并发检测 ----------------
    log("\n🔍 [阶段二] 开始 API 地区测定与 TCP 延迟测试...\n")

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

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(process_task, ip, port, st): (ip, port, st) for ip, port, st in all_tasks}
        for future in as_completed(futures):
            res = future.result()
            if res:
                ip, port, region, latency, st = res
                log(f"   [存活] {ip}:{port} | 真实地区: {region} | 延迟: {latency}ms | 组别: {st}")
                if st == "DOMAIN":
                    domain_verified[region].append((ip, port, latency))
                else:
                    sub_verified[region].append((ip, port, latency))

    # ---------------- 阶段 3：按地区分组挑选与处理 ----------------
    log("\n💾 [阶段三] 严格按照【各地区分别取前 5】的规则进行分配...\n")

    domain_output_lines = []
    sub_output_lines = []

    # 按各允许的地区循环遍历 (HK, JP, SG, TW, US)
    for region in sorted(ALLOWED_REGIONS):
        log(f"🌍 正在处理地区: 【{region}】")

        # 【域名源 (DOMAIN)】处理逻辑
        domain_pool = domain_verified.get(region, [])
        # 对当前地区的域名源池子，按延迟升序排序，然后只切片取前 TOP_N(5) 个！
        domain_top5 = sorted(domain_pool, key=lambda x: x[2])[:TOP_N]
        log(f"   [域名源] 该地区存活 {len(domain_pool)} 个，选出延迟最低的前 {len(domain_top5)} 个！")
        
        if domain_top5:
            ips_for_dns = [node[0] for node in domain_top5]
            # 专属动作：仅把域名源选出的当前地区的 IP，推送到当前地区绑定的 CF 域名
            update_cloudflare_dns(region, ips_for_dns)
            
            for ip, port, lat in domain_top5:
                domain_output_lines.append(f"{ip}#{region}")

        # 【订阅源 (SUB)】处理逻辑
        sub_pool = sub_verified.get(region, [])
        # 同样，对当前地区的订阅源池子，按延迟排序，取前 TOP_N(5) 个！
        sub_top5 = sorted(sub_pool, key=lambda x: x[2])[:TOP_N]
        log(f"   [订阅源] 该地区存活 {len(sub_pool)} 个，选出延迟最低的前 {len(sub_top5)} 个！")
        
        if sub_top5:
            # 专属动作：订阅源只写文件，坚决不更新 CF
            for ip, port, lat in sub_top5:
                sub_output_lines.append(f"{ip}:{port}#{region}")
                
        log("-" * 40)

    # ---------------- 最终写入文件 ----------------
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(domain_output_lines))
    
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sub_output_lines))

    log("\n" + "="*65)
    log(f"🎉 完美完工汇总：")
    log(f"   ✅ 按地区写入 domain_ips.txt 共 {len(domain_output_lines)} 行 (最多 5 * {len(ALLOWED_REGIONS)} = 25行)")
    log(f"   ✅ 按地区写入 other_ips.txt 共 {len(sub_output_lines)} 行 (最多 5 * {len(ALLOWED_REGIONS)} = 25行)")
    log("="*65)

if __name__ == "__main__":
    main()
