import requests
import base64
import json
import re
import socket
import dns.resolver
import dns.rdatatype
import dns.name
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import subprocess
import threading

# ================= 配置区域 =================
SOURCES = [
    # 域名类（DNS解析）
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.JP.CMLiussss.net",
    "sjc.o00o.ooo",
    "tw.william.us.ci",
    "proxy.xinyitang.dpdns.org",
    # 订阅链接类（HTTP请求）
    "https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F"
]

DOMAIN_REGION_HINT = {
    "ProxyIP.HK.CMLiussss.net": "HK",
    "ProxyIP.JP.CMLiussss.net": "JP",
    "sjc.o00o.ooo":             "US",
    "tw.william.us.ci":         "TW",
    "proxy.xinyitang.dpdns.org":"HK",
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

# 多个DNS服务器，优先级排序
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
            # 禁用缓存
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
        
        # 先尝试直接A记录
        for dns_server, _ in PUBLIC_DNS_SERVERS:
            results = self.query_single_dns(domain, dns_server, 'A', timeout=4)
            ips.update(results)
        
        # 再尝试CNAME
        for dns_server, _ in PUBLIC_DNS_SERVERS[:3]:  # 只用前3个DNS查CNAME，加速
            cnames = self.query_single_dns(domain, dns_server, 'CNAME', timeout=4)
            for cname in cnames:
                # 递归查CNAME目标
                cname_ips = self.resolve_cname_chain(cname, depth + 1, max_depth, visited)
                ips.update(cname_ips)
        
        return ips
    
    def resolve_via_doh(self, domain):
        """DNS-over-HTTPS查询（可穿透某些DNS污染）"""
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
                    if answer.get("type") == 1:  # A记录
                        ip = answer.get("data", "")
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            ips.add(ip)
            except Exception:
                pass
        
        return ips
    
    def resolve_via_system_nslookup(self, domain):
        """调用系统 nslookup 命令（可能绕过python dns库限制）"""
        ips = set()
        try:
            # Linux/Mac
            result = subprocess.run(
                ["nslookup", domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                # 匹配 "Address: 1.2.3.4" 行
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
            # 用dig查询，跳过系统缓存
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
    
    def resolve_all_methods(self, domain):
        """综合所有方法解析域名"""
        all_ips = set()
        
        print(f"    [DNS] 开始多方法解析: {domain}")
        
        # 方法1: CNAME链递归
        try:
            cname_ips = self.resolve_cname_chain(domain)
            if cname_ips:
                print(f"      └─ CNAME链: {len(cname_ips)} IP")
                all_ips.update(cname_ips)
        except Exception as e:
            print(f"      └─ CNAME链失败: {e}")
        
        # 方法2: DoH
        try:
            doh_ips = self.resolve_via_doh(domain)
            if doh_ips:
                print(f"      └─ DoH: {len(doh_ips)} IP")
                all_ips.update(doh_ips)
        except Exception as e:
            print(f"      └─ DoH失败: {e}")
        
        # 方法3: 系统nslookup
        try:
            nslookup_ips = self.resolve_via_system_nslookup(domain)
            if nslookup_ips:
                print(f"      └─ nslookup: {len(nslookup_ips)} IP")
                all_ips.update(nslookup_ips)
        except Exception as e:
            print(f"      └─ nslookup失败: {e}")
        
        # 方法4: 系统dig
        try:
            dig_ips = self.resolve_via_dig(domain)
            if dig_ips:
                print(f"      └─ dig: {len(dig_ips)} IP")
                all_ips.update(dig_ips)
        except Exception as e:
            print(f"      └─ dig失败: {e}")
        
        # 方法5: 多次并发查询同一个DNS（获取不同的负载均衡IP）
        try:
            concurrent_ips = set()
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [
                    executor.submit(self.query_single_dns, domain, "8.8.8.8", 'A')
                    for _ in range(8)
                ]
                for future in as_completed(futures):
                    concurrent_ips.update(future.result())
            if concurrent_ips:
                print(f"      └─ 并发查询: {len(concurrent_ips)} IP")
                all_ips.update(concurrent_ips)
        except Exception as e:
            print(f"      └─ 并发查询失败: {e}")
        
        # 方法6: 多个公共DNS并发查询
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
        
        print(f"    ✓ {domain} 最终解析到 {len(all_ips)} 个IP: {all_ips}\n")
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
    """调用在线API检测节点可用性，带重试机制"""
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
                time.sleep(2)
    
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
            time.sleep(0.2)
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
        # 删除旧记录
        get_resp = requests.get(
            base_url, headers=headers, params={"name": record_name}, timeout=10
        ).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                del_resp = requests.delete(
                    f"{base_url}/{rec['id']}", headers=headers, timeout=10
                ).json()
                if del_resp.get("success"):
                    print(f"  [-] 删除旧记录: {rec['id']}")
        
        # 写入新记录
        for ip in ips:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False,
            }
            post_resp = requests.post(
                base_url, headers=headers, json=data, timeout=10
            ).json()
            status = "✓" if post_resp.get("success") else "✗"
            print(f"  [{status}] 添加 {ip}")
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
    """检测单个节点"""
    is_ok, real_region = check_availability(ip, port)
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

            # vmess
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

            # vless / trojan / ss / hy2
            elif "://" in line and "@" in line:
                match = re.search(r'@([^:@\s]+):(\d+)', line)
                if match:
                    addr = match.group(1)
                    port = match.group(2)
                    label = line.split("#")[-1] if "#" in line else line
                    tag = extract_country_local(label)

            # 纯IP
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
    print("\n" + "=" * 60)
    print("🚀 ProxyIP 节点收集工具 v2.0")
    print("=" * 60 + "\n")

    dns_resolver = DNSResolver()
    domain_raw: dict[str, set] = {}
    sub_raw_data: set = set()

    # ===== 阶段1：收集原始数据 =====
    print("[1/4] 📡 收集原始节点数据...\n")

    for src in SOURCES:
        if src.startswith("http"):
            print(f"  📥 [订阅] {src[:70]}")
            nodes = fetch_subscription(src)
            print(f"     ✓ 解析到 {len(nodes)} 个节点\n")
            sub_raw_data.update(nodes)
        else:
            hint = DOMAIN_REGION_HINT.get(src, "UN")
            ips = dns_resolver.resolve_all_methods(src)
            domain_raw[src] = ips

    # 汇总域名IP
    domain_ip_hint: dict[str, str] = {}
    for domain, ips in domain_raw.items():
        hint = DOMAIN_REGION_HINT.get(domain, "UN")
        for ip in ips:
            if ip not in domain_ip_hint or domain_ip_hint[ip] == "UN":
                domain_ip_hint[ip] = hint

    total_domain_raw = len(domain_ip_hint)
    total_sub_raw = len(sub_raw_data)

    print("\n" + "=" * 60)
    print(f"📊 收集结果: 域名源={total_domain_raw} IP  |  订阅源={total_sub_raw} 节点")
    print("=" * 60 + "\n")

    # ===== 阶段2：检测域名IP =====
    print("[2/4] 🔍 检测域名源IP...\n")

    domain_verified_groups: dict[str, list] = defaultdict(list)
    tested_ips = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(process_node, ip, "443", hint): ip
            for ip, hint in domain_ip_hint.items()
        }
        
        for future in as_completed(future_map):
            tested_ips += 1
            res = future.result()
            if res:
                domain_verified_groups[res["tag"]].append(res)
                print(f"  ✓ [{tested_ips}/{total_domain_raw}] {res['ip']}:{res['port']} "
                      f"| {res['tag']} | {res['latency']}ms")
            else:
                if tested_ips % 5 == 0:
                    print(f"  ✗ [{tested_ips}/{total_domain_raw}] 测试中...")

    total_domain_ok = sum(len(v) for v in domain_verified_groups.values())
    print(f"\n  ✓ 域名源通过: {total_domain_ok}/{total_domain_raw}\n")

    # ===== 阶段3：检测订阅IP =====
    print("[3/4] 🔍 检测订阅源IP...\n")

    sub_verified_groups: dict[str, list] = defaultdict(list)
    tested_nodes = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(process_node, ip, port, tag): (ip, port, tag)
            for ip, port, tag in sub_raw_data
        }
        
        for future in as_completed(future_map):
            tested_nodes += 1
            res = future.result()
            if res:
                sub_verified_groups[res["tag"]].append(res)
                print(f"  ✓ [{tested_nodes}/{total_sub_raw}] {res['ip']}:{res['port']} "
                      f"| {res['tag']} | {res['latency']}ms")
            else:
                if tested_nodes % 5 == 0:
                    print(f"  ✗ [{tested_nodes}/{total_sub_raw}] 测试中...")

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

    # 4-D: 统计汇总
    print("\n" + "=" * 60)
    print("📈 最终统计")
    print("=" * 60)
    print(f"\n  domain_ips.txt ({len(domain_out_lines)} 行):")
    for region in sorted(ALLOWED_REGIONS):
        count = len([x for x in domain_out_lines if f"#{region}" in x])
        print(f"    {region}: {count:3d} 个")

    print(f"\n  other_ips.txt ({len(other_out_lines)} 行):")
    for region in sorted(ALLOWED_REGIONS):
        count = len([x for x in other_out_lines if f"#{region}" in x])
        print(f"    {region}: {count:3d} 个")

    print("\n" + "=" * 60)
    print("✅ 任务完成!\n")


if __name__ == "__main__":
    main()
