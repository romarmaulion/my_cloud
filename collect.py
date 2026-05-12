import requests
import base64
import json
import re
import socket
import dns.resolver
import dns.rdatatype
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import subprocess
import threading

# ================= 配置区域 =================
SOURCES = [
    # 明确的地区域名（通常只返回该地区IP）
    ("ProxyIP.HK.CMLiussss.net", "SINGLE"),    # 域名本身标注了地区
    ("ProxyIP.JP.CMLiussss.net", "SINGLE"),    # 域名本身标注了地区
    
    # 混合负载均衡域名（返回多地区IP，需要用API探测真实地区）
    ("sjc.o00o.ooo", "LB"),                    # SJC = San Jose，但可能LB返回多IP
    ("tw.william.us.ci", "MIXED"),             # 看起来是TW但可能混合
    ("proxy.xinyitang.dpdns.org", "LB"),       # 明确的LB域名，多地区
    
    # 订阅链接
    ("https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F", "SUB"),
    ("https://sub.cmliussss.net/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F", "SUB"),
    ("https://owo.o00o.ooo/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F", "SUB"),
]

# 域名类型说明：
# SINGLE: 域名名称本身明确标注地区（如 ProxyIP.HK），返回IP应该都是该地区
# MIXED:  域名名称有提示但不明确，可能混合多个地区
# LB:     明确的负载均衡域名，返回多个地区的IP，需要逐个检测

# 对于SINGLE和MIXED类型的初始地区提示（仅用于无法检测时的备选）
DOMAIN_REGION_HINT = {
    "ProxyIP.HK.CMLiussss.net": ("HK", "SINGLE"),    # (地区提示, 源类型)
    "ProxyIP.JP.CMLiussss.net": ("JP", "SINGLE"),
    "sjc.o00o.ooo":             ("US", "MIXED"),     # SJC可能是，但要检测
    "tw.william.us.ci":         ("TW", "MIXED"),
    "proxy.xinyitang.dpdns.org":("UN", "LB"),        # LB域名不做地区假设！
}

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
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
    "TW": os.getenv("CF_RECORD_TW"),
}

PUBLIC_DNS_SERVERS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("208.67.222.222", "OpenDNS"),
    ("9.9.9.9", "Quad9"),
    ("114.114.114.114", "114 DNS"),
    ("180.76.76.76", "Baidu DNS"),
    ("119.29.29.29", "DNSPod"),
]

# ===========================================

class DNSResolver:
    """强化版DNS解析器"""
    
    def __init__(self):
        self.ips_cache = {}
        self.lock = threading.Lock()
    
    def query_single_dns(self, domain, dns_server, rdtype='A', timeout=5):
        """单个DNS服务器查询单条记录"""
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout * 2
            resolver.cache = None
            
            answers = resolver.resolve(domain, rdtype)
            results = []
            
            for rdata in answers:
                if rdtype == 'A':
                    results.append(rdata.address)
                elif rdtype == 'CNAME':
                    results.append(str(rdata.target).rstrip('.'))
                elif rdtype == 'MX':
                    results.append(str(rdata.exchange).rstrip('.'))
                elif rdtype == 'NS':
                    results.append(str(rdata.target).rstrip('.'))
            
            return results
        except Exception:
            return []
    
    def resolve_cname_chain(self, domain, depth=0, max_depth=8, visited=None):
        """递归解析CNAME链"""
        if visited is None:
            visited = set()
        
        if depth > max_depth or domain in visited:
            return set()
        
        visited.add(domain)
        ips = set()
        
        for dns_server, _ in PUBLIC_DNS_SERVERS:
            results = self.query_single_dns(domain, dns_server, 'A', timeout=4)
            ips.update(results)
        
        for dns_server, _ in PUBLIC_DNS_SERVERS[:3]:
            cnames = self.query_single_dns(domain, dns_server, 'CNAME', timeout=4)
            for cname in cnames:
                cname_ips = self.resolve_cname_chain(cname, depth + 1, max_depth, visited)
                ips.update(cname_ips)
        
        return ips
    
    def resolve_via_doh(self, domain):
        """DNS-over-HTTPS查询"""
        ips = set()
        
        doh_servers = [
            ("https://dns.google/resolve", "Google DoH"),
            ("https://cloudflare-dns.com/dns-query", "Cloudflare DoH"),
            ("https://doh.opendns.com/dns-query", "OpenDNS DoH"),
            ("https://dns.quad9.net/dns-query", "Quad9 DoH"),
        ]
        
        for doh_url, name in doh_servers:
            try:
                params = {"name": domain, "type": "A"}
                headers = {"accept": "application/dns-json"}
                resp = requests.get(
                    doh_url, params=params, headers=headers, timeout=8
                ).json()
                
                for answer in resp.get("Answer", []):
                    if answer.get("type") == 1:
                        ip = answer.get("data", "")
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            ips.add(ip)
            except Exception:
                pass
        
        return ips
    
    def resolve_via_system_nslookup(self, domain):
        """调用系统 nslookup 命令"""
        ips = set()
        try:
            result = subprocess.run(
                ["nslookup", domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    ips.add(match.group(1))
        except Exception:
            pass
        
        return ips
    
    def resolve_via_dig(self, domain):
        """调用系统 dig 命令查询"""
        ips = set()
        try:
            result = subprocess.run(
                ["dig", "+short", domain, "A", "+nocmd"],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.strip().split('\n'):
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.strip()):
                    ips.add(line.strip())
        except Exception:
            pass
        
        return ips
    
    def resolve_all_methods(self, domain, source_type="LB"):
        """综合所有方法解析域名"""
        all_ips = set()
        
        print(f"    [DNS] 解析 {domain} (类型:{source_type})")
        
        try:
            cname_ips = self.resolve_cname_chain(domain)
            if cname_ips:
                print(f"      └─ CNAME链: {len(cname_ips)} IP")
                all_ips.update(cname_ips)
        except Exception as e:
            print(f"      └─ CNAME链失败: {e}")
        
        try:
            doh_ips = self.resolve_via_doh(domain)
            if doh_ips:
                print(f"      └─ DoH: {len(doh_ips)} IP")
                all_ips.update(doh_ips)
        except Exception as e:
            print(f"      └─ DoH失败: {e}")
        
        try:
            nslookup_ips = self.resolve_via_system_nslookup(domain)
            if nslookup_ips:
                print(f"      └─ nslookup: {len(nslookup_ips)} IP")
                all_ips.update(nslookup_ips)
        except Exception as e:
            print(f"      └─ nslookup失败: {e}")
        
        try:
            dig_ips = self.resolve_via_dig(domain)
            if dig_ips:
                print(f"      └─ dig: {len(dig_ips)} IP")
                all_ips.update(dig_ips)
        except Exception as e:
            print(f"      └─ dig失败: {e}")
        
        # 对LB和MIXED域名，多次并发查询以获取所有轮询IP
        if source_type in ["LB", "MIXED"]:
            try:
                concurrent_ips = set()
                with ThreadPoolExecutor(max_workers=15) as executor:
                    futures = [
                        executor.submit(self.query_single_dns, domain, "8.8.8.8", 'A')
                        for _ in range(15)  # 15次查询，最大化获取不同的LB IP
                    ]
                    for future in as_completed(futures):
                        concurrent_ips.update(future.result())
                if concurrent_ips:
                    print(f"      └─ 并发查询(15x): {len(concurrent_ips)} IP")
                    all_ips.update(concurrent_ips)
            except Exception as e:
                print(f"      └─ 并发查询失败: {e}")
        
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(
                        self.query_single_dns, domain, server, 'A', timeout=4
                    ): name
                    for server, name in PUBLIC_DNS_SERVERS
                }
                for future in as_completed(futures):
                    all_ips.update(future.result())
            print(f"      └─ 公共DNS: 并发完成")
        except Exception as e:
            print(f"      └─ 公共DNS失败: {e}")
        
        print(f"    ✓ 最终收集 {len(all_ips)} 个IP\n")
        return all_ips


def extract_country_local(label):
    """从节点标签提取国家代码"""
    label = label.upper()
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first  = ord(emoji_chars[0]) - 0x1F1E6
        second = ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    
    cn_map = {
        "香港": "HK", "日本": "JP", "新加坡": "SG",
        "台湾": "TW", "台灣": "TW", "美国": "US", "美國": "US",
    }
    for name, code in cn_map.items():
        if name in label:
            return code
    
    en_map = {
        "HK": "HK", "HONG KONG": "HK", "HONGKONG": "HK",
        "JP": "JP", "JAPAN": "JP",
        "SG": "SG", "SINGAPORE": "SG",
        "TW": "TW", "TAIWAN": "TW",
        "US": "US", "UNITED STATES": "US", "AMERICA": "US",
    }
    for kw, code in en_map.items():
        if kw in label:
            return code
    
    return "UN"


def check_availability(ip, port, retries=2):
    """调用API检测节点可用性，获取真实地区"""
    for attempt in range(retries):
        try:
            resp = requests.get(
                CHECK_API,
                params={"proxyip": f"{ip}:{port}"},
                timeout=20,
            ).json()
            if resp.get("success") is True:
                region = (
                    resp.get("probe_results", {})
                        .get("ipv4", {})
                        .get("exit", {})
                        .get("country", "UN")
                        .upper()
                )
                return True, region
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
    
    return False, "UN"


def tcp_ping(ip, port, timeout=3):
    """TCP握手延迟测试"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, int(port)))
        sock.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return 99999


def multi_ping(ip, port, count=3):
    """多次TCP ping取最小值"""
    results = []
    for _ in range(count):
        lat = tcp_ping(ip, port, timeout=3)
        if lat < 99999:
            results.append(lat)
        if _ < count - 1:
            time.sleep(0.1)
    return min(results) if results else 99999


def update_dns_record(record_name, ips):
    """更新 Cloudflare DNS 记录"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not record_name:
        print(f"[!] 缺少 CF 配置，跳过 DNS 更新: {record_name}")
        return
    
    ips = sorted(set(ips))
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    
    try:
        print(f"[*] 正在更新域名: {record_name}  IP列表: {ips}")
        get_resp = requests.get(
            base_url, headers=headers, params={"name": record_name}, timeout=10
        ).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(
                    f"{base_url}/{rec['id']}", headers=headers, timeout=10
                )
        
        for ip in ips:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False,
            }
            requests.post(base_url, headers=headers, json=data, timeout=10)
            print(f"  [+] 添加 {ip}")
    except Exception as e:
        print(f"[!] DNS更新出错: {e}")


def get_region_domain(region_code):
    """获取地区对应的 DNS 记录名"""
    custom = CUSTOM_DOMAIN_MAP.get(region_code)
    if custom:
        return custom
    if CF_BASE_DOMAIN:
        return f"{region_code.lower()}.{CF_BASE_DOMAIN}"
    return None


def process_node(ip, port, initial_tag):
    """检测单个节点，获取真实地区"""
    # ⭐ 关键：总是调用API检测真实地区，不依赖初始标签
    is_ok, real_region = check_availability(ip, port)
    
    # 使用真实地区，如果检测失败才用初始标签作备选
    tag = real_region if real_region != "UN" else initial_tag
    
    if is_ok and tag in ALLOWED_REGIONS:
        latency = multi_ping(ip, port)
        if latency < 2000:
            return {
                "ip": ip,
                "port": port,
                "tag": tag,
                "latency": latency,
            }
    return None


def fetch_subscription(url):
    """抓取订阅链接"""
    nodes = set()
    try:
        headers = {
            "User-Agent": "v2rayNG/1.8.5",
            "Accept": "*/*",
        }
        content = requests.get(url, headers=headers, timeout=20).text

        try:
            decoded = base64.b64decode(
                content + "=" * (-len(content) % 4)
            ).decode("utf-8")
        except Exception:
            decoded = content

        for line in decoded.splitlines():
            line = line.strip()
            if not line:
                continue

            addr, port, tag = "", "443", "UN"

            if line.startswith("vmess://"):
                try:
                    v2 = json.loads(
                        base64.b64decode(line[8:] + "==").decode("utf-8")
                    )
                    addr = v2.get("add", "")
                    port = str(v2.get("port", "443"))
                    tag  = extract_country_local(v2.get("ps", ""))
                except Exception:
                    pass

            elif "://" in line and "@" in line:
                match = re.search(r'@([^:@\s]+):(\d+)', line)
                if match:
                    addr = match.group(1)
                    port = match.group(2)
                    label = line.split("#")[-1] if "#" in line else line
                    tag = extract_country_local(label)

            else:
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?', line)
                if match:
                    addr = match.group(1)
                    port = match.group(2) if match.group(2) else "443"
                    label = line.split("#")[-1] if "#" in line else line
                    tag = extract_country_local(label)

            if addr and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', addr):
                nodes.add((addr, str(port), tag))

    except Exception as e:
        print(f"  [!] 订阅抓取失败 {url}: {e}")

    return nodes


def main():
    print("\n" + "=" * 70)
    print("🚀 ProxyIP 节点收集工具 v3.0 (智能LB域名处理)")
    print("=" * 70 + "\n")

    dns_resolver = DNSResolver()
    domain_raw: dict[str, set] = {}  # domain -> IPs
    sub_raw_data: set = set()

    # ===== 阶段1：收集原始数据 =====
    print("[1/4] 📡 收集原始节点数据...\n")

    for src, *extra in SOURCES:
        if src.startswith("http"):
            print(f"  📥 [订阅] {src[:70]}")
            nodes = fetch_subscription(src)
            print(f"     ✓ 解析到 {len(nodes)} 个节点\n")
            sub_raw_data.update(nodes)
        else:
            # 获取源的类型
            if src in DOMAIN_REGION_HINT:
                hint, source_type = DOMAIN_REGION_HINT[src]
            else:
                hint, source_type = "UN", "LB"
            
            # ⭐ 关键改进：根据源类型选择DNS解析策略
            ips = dns_resolver.resolve_all_methods(src, source_type)
            domain_raw[src] = (ips, hint, source_type)

    # 汇总域名IP（去重，保留元数据）
    domain_ip_with_meta: dict[str, tuple] = {}  # ip -> (domain, hint, source_type)
    for domain, (ips, hint, source_type) in domain_raw.items():
        for ip in ips:
            if ip not in domain_ip_with_meta:
                domain_ip_with_meta[ip] = (domain, hint, source_type)

    total_domain_raw = len(domain_ip_with_meta)
    total_sub_raw = len(sub_raw_data)

    print("\n" + "=" * 70)
    print(f"📊 收集结果: 域名源={total_domain_raw} IP  |  订阅源={total_sub_raw} 节点")
    print("=" * 70 + "\n")

    # ===== 阶段2：检测域名IP =====
    print("[2/4] 🔍 检测域名源IP (逐个API检测真实地区)...\n")

    domain_verified_groups: dict[str, list] = defaultdict(list)
    tested_ips = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        # ⭐ 关键：不使用初始地区提示，而是用"UN"强制API检测
        future_map = {
            executor.submit(process_node, ip, "443", "UN"): (ip, meta)
            for ip, meta in domain_ip_with_meta.items()
        }
        
        for future in as_completed(future_map):
            tested_ips += 1
            res = future.result()
            if res:
                domain_verified_groups[res["tag"]].append(res)
                domain, hint, stype = future_map[future][1]
                print(f"  ✓ [{tested_ips:4d}/{total_domain_raw}] {res['ip']}:{res['port']} "
                      f"| {res['tag']:2s} | {res['latency']:5d}ms | from:{domain} (hint:{hint})")
            else:
                if tested_ips % 10 == 0:
                    print(f"  ⏳ [{tested_ips:4d}/{total_domain_raw}] 测试中...")

    total_domain_ok = sum(len(v) for v in domain_verified_groups.values())
    print(f"\n  ✓ 域名源通过: {total_domain_ok}/{total_domain_raw}\n")

    # ===== 阶段3：检测订阅IP =====
    print("[3/4] 🔍 检测订阅源IP (逐个API检测真实地区)...\n")

    sub_verified_groups: dict[str, list] = defaultdict(list)
    tested_nodes = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        # ⭐ 订阅源的IP通常已有标签，但也要通过API检测以确保准确
        future_map = {
            executor.submit(process_node, ip, port, tag): (ip, port, tag)
            for ip, port, tag in sub_raw_data
        }
        
        for future in as_completed(future_map):
            tested_nodes += 1
            res = future.result()
            if res:
                sub_verified_groups[res["tag"]].append(res)
                orig_ip, orig_port, orig_tag = future_map[future]
                status = "✓" if res["tag"] == orig_tag else "✓(修正)"
                print(f"  {status} [{tested_nodes:4d}/{total_sub_raw}] {res['ip']}:{res['port']} "
                      f"| {res['tag']:2s} | {res['latency']:5d}ms | orig_tag:{orig_tag}")
            else:
                if tested_nodes % 10 == 0:
                    print(f"  ⏳ [{tested_nodes:4d}/{total_sub_raw}] 测试中...")

    total_sub_ok = sum(len(v) for v in sub_verified_groups.values())
    print(f"\n  ✓ 订阅源通过: {total_sub_ok}/{total_sub_raw}\n")

    # ===== 阶段4：输出结果 =====
    print("[4/4] 💾 输出结果...\n")

    # 4-A: 更新 Cloudflare DNS
    print("  📌 同步到 Cloudflare DNS:")
    for region in sorted(ALLOWED_REGIONS):
        nodes = domain_verified_groups.get(region, [])
        if nodes:
            sorted_nodes = sorted(nodes, key=lambda x: x["latency"])[:TOP_N]
            target_domain = get_region_domain(region)
            if target_domain:
                print(f"    {region}: {len(sorted_nodes)} 节点 → {target_domain}")
                update_dns_record(target_domain, [n["ip"] for n in sorted_nodes])
        else:
            print(f"    {region}: ⚠️  无可用节点")

    # 4-B: 保存 domain_ips.txt
    domain_out_lines = []
    for region in sorted(ALLOWED_REGIONS):
        for n in sorted(domain_verified_groups.get(region, []), key=lambda x: x["latency"]):
            domain_out_lines.append(f"{n['ip']}#{n['tag']}")

    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(domain_out_lines))

    # 4-C: 保存 other_ips.txt
    other_out_lines = []
    for region in sorted(ALLOWED_REGIONS):
        nodes = sorted(sub_verified_groups.get(region, []), key=lambda x: x["latency"])[:TOP_N]
        for n in nodes:
            other_out_lines.append(f"{n['ip']}:{n['port']}#{n['tag']}")

    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(other_out_lines))

    # 4-D: 汇总统计
    print("\n" + "=" * 70)
    print("📈 最终统计")
    print("=" * 70)
    print(f"\n  domain_ips.txt ({len(domain_out_lines)} 行):")
    for region in sorted(ALLOWED_REGIONS):
        count = len([x for x in domain_out_lines if f"#{region}" in x])
        print(f"    {region}: {count:3d} 个")

    print(f"\n  other_ips.txt ({len(other_out_lines)} 行):")
    for region in sorted(ALLOWED_REGIONS):
        count = len([x for x in other_out_lines if f"#{region}" in x])
        print(f"    {region}: {count:3d} 个")

    print("\n" + "=" * 70)
    print("✅ 任务完成!\n")


if __name__ == "__main__":
    main()
