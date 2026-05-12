import requests
import base64
import json
import re
import socket
import dns.resolver
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import subprocess
import threading
import urllib.parse

# ================= 配置区域 =================
SOURCES = [
    ("ProxyIP.HK.CMLiussss.net", "SINGLE"),
    ("ProxyIP.JP.CMLiussss.net", "SINGLE"),
    ("sjc.o00o.ooo", "LB"),
    ("tw.william.us.ci", "MIXED"),
    ("proxy.xinyitang.dpdns.org", "LB"),
    
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

DOMAIN_REGION_HINT = {
    "ProxyIP.HK.CMLiussss.net": ("HK", "SINGLE"),
    "ProxyIP.JP.CMLiussss.net": ("JP", "SINGLE"),
    "sjc.o00o.ooo":             ("US", "MIXED"),
    "tw.william.us.ci":         ("TW", "MIXED"),
    "proxy.xinyitang.dpdns.org":("UN", "LB"),
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
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "9.9.9.9",
    "114.114.114.114",
    "119.29.29.29",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "v2rayNG/1.8.5",
]

# ===========================================


class CloudflareBypassHTTPClient:
    """支持Cloudflare绕过的HTTP客户端"""
    
    def __init__(self):
        self.user_agent_idx = 0
    
    def _get_user_agent(self):
        ua = USER_AGENTS[self.user_agent_idx % len(USER_AGENTS)]
        self.user_agent_idx += 1
        return ua
    
    def _fetch_with_requests(self, url, timeout=20):
        """用requests尝试（可能被CF拦截）"""
        try:
            headers = {
                "User-Agent": self._get_user_agent(),
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Sec-Ch-Ua": '"Chromium";v="91", " Not;A Brand";v="99"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
            
            session = requests.Session()
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            return resp.text if resp.status_code == 200 else None
        except Exception:
            return None
    
    def _fetch_with_curl(self, url, timeout=20):
        """用curl绕过CF（推荐）"""
        try:
            cmd = [
                "curl",
                "-s",
                "-L",
                "-A", self._get_user_agent(),
                "-b", "/tmp/cookies.txt",
                "-c", "/tmp/cookies.txt",
                "--compressed",
                "--max-time", str(timeout),
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None
    
    def _fetch_with_wget(self, url, timeout=20):
        """用wget备选"""
        try:
            cmd = [
                "wget",
                "-q",
                "-O", "-",
                "-U", self._get_user_agent(),
                "--save-cookies=/tmp/cookies.txt",
                "--keep-session-cookies",
                "--timeout=" + str(timeout),
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None
    
    def fetch(self, url):
        """多方法获取，优先级：curl > wget > requests"""
        print(f"       [*] 正在获取内容...", end="", flush=True)
        
        # 方法1: curl（最强CF绕过能力）
        content = self._fetch_with_curl(url)
        if content and not self._is_cf_challenge(content):
            print(" ✓ (curl)")
            return content
        
        # 方法2: wget
        content = self._fetch_with_wget(url)
        if content and not self._is_cf_challenge(content):
            print(" ✓ (wget)")
            return content
        
        # 方法3: requests（通常被CF拦截）
        content = self._fetch_with_requests(url)
        if content and not self._is_cf_challenge(content):
            print(" ✓ (requests)")
            return content
        
        print(" ✗ (全部失败)")
        return None
    
    @staticmethod
    def _is_cf_challenge(content):
        """检测是否是CF挑战页面"""
        if not content:
            return True
        
        cf_indicators = [
            "Just a moment",
            "Checking your browser",
            "Enable JavaScript and cookies",
            "cf_clearance",
            "cf_challenge",
            "challenge-form",
        ]
        
        return any(indicator in content for indicator in cf_indicators)


class DNSResolver:
    """DNS解析器"""
    
    def query_single_dns(self, domain, dns_server, rdtype='A', timeout=5):
        """单个DNS查询"""
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout * 2
            resolver.cache = None
            answers = resolver.resolve(domain, rdtype)
            if rdtype == 'A':
                return [rdata.address for rdata in answers]
            elif rdtype == 'CNAME':
                return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception:
            return []
        return []
    
    def resolve_via_socket(self, domain):
        """系统socket解析（备用）"""
        try:
            return [socket.gethostbyname(domain)]
        except Exception:
            return []
    
    def resolve_fast(self, domain):
        """快速解析域名"""
        ips = set()
        for dns_server in PUBLIC_DNS_SERVERS[:3]:
            results = self.query_single_dns(domain, dns_server, 'A', timeout=3)
            if results:
                ips.update(results)
                break
        
        if not ips:
            ips.update(self.resolve_via_socket(domain))
        
        return ips


def extract_country_local(label):
    """从节点标签提取国家代码"""
    if not label:
        return "UN"
    label = label.upper()
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first  = ord(emoji_chars[0]) - 0x1F1E6
        second = ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    
    cn_map = {
        "香港": "HK", "日本": "JP", "新加坡": "SG",
        "台湾": "TW", "台灣": "TW", "美国": "US", "美國": "US"
    }
    for name, code in cn_map.items():
        if name in label:
            return code
    
    en_map = {
        "HK": "HK", "HONG KONG": "HK", "HONGKONG": "HK",
        "JP": "JP", "JAPAN": "JP",
        "SG": "SG", "SINGAPORE": "SG",
        "TW": "TW", "TAIWAN": "TW",
        "US": "US", "UNITED STATES": "US", "AMERICA": "US", "USA": "US"
    }
    for kw, code in en_map.items():
        if kw in label:
            return code
    return "UN"


def safe_b64decode(data):
    """安全的base64解码"""
    if not data:
        return None
    data = data.strip()
    data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return None


def parse_node_line(line):
    """解析单条节点链接"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    host, port, tag, protocol = "", "443", "UN", "unknown"
    
    # vmess
    if line.startswith("vmess://"):
        try:
            b64_data = line[8:]
            decoded = safe_b64decode(b64_data)
            if not decoded:
                return None
            v2 = json.loads(decoded)
            host = v2.get("add", "")
            port = str(v2.get("port", "443"))
            tag = extract_country_local(v2.get("ps", ""))
            protocol = "vmess"
        except Exception:
            return None
    
    # vless / trojan / hysteria2 / ss
    elif "://" in line:
        body = line
        if "#" in line:
            body, label = line.rsplit("#", 1)
            try:
                label = urllib.parse.unquote(label)
            except:
                pass
            tag = extract_country_local(label)
        
        protocol = line.split("://")[0].lower()
        after_proto = body.split("://", 1)[1] if "://" in body else body
        
        host_part = after_proto
        if "@" in after_proto:
            _, host_part = after_proto.rsplit("@", 1)
        
        host_port_str = host_part.split("/")[0].split("?")[0]
        
        if host_port_str.startswith("["):
            match = re.search(r'^\[([0-9a-fA-F:]+)\]:(\d+)', host_port_str)
            if match:
                host = match.group(1)
                port = match.group(2)
        else:
            match = re.match(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]|\d+\.\d+\.\d+\.\d+):(\d+)', host_port_str)
            if match:
                host = match.group(1)
                port = match.group(2)
            else:
                match = re.match(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]|\d+\.\d+\.\d+\.\d+)$', host_port_str)
                if match:
                    host = match.group(1)
                    port = "443"
    
    else:
        match = re.match(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]|\d+\.\d+\.\d+\.\d+)(?::(\d+))?', line)
        if match:
            host = match.group(1)
            port = match.group(2) if match.group(2) else "443"
            label = line.split("#")[-1] if "#" in line else line
            tag = extract_country_local(label)
    
    if not host or host in ["", "127.0.0.1", "localhost", "0.0.0.0"]:
        return None
    
    return (host, str(port), tag, protocol)


def fetch_subscription(url):
    """抓取订阅链接，自动绕过CF"""
    nodes = set()
    raw_domains = []
    
    try:
        http_client = CloudflareBypassHTTPClient()
        content = http_client.fetch(url)
        
        if not content:
            print(f"       [!] 无法获取内容 (CF拦截或网络问题)")
            return set()
        
        # 显示内容摘要
        preview = content[:150].replace('\n', ' ')
        if len(preview) > 145:
            preview = preview[:145] + "..."
        print(f"       原始内容: {preview}")
        print(f"       内容长度: {len(content)} 字符")

        decoded = safe_b64decode(content)
        if decoded:
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            print(f"       Base64解码成功，行数: {len(lines)}")
        else:
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            print(f"       非Base64内容，行数: {len(lines)}")

        valid_lines = 0
        for line in lines:
            parsed = parse_node_line(line)
            if not parsed:
                continue
            
            valid_lines += 1
            host, port, tag, protocol = parsed
            
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                nodes.add((host, port, tag))
            else:
                raw_domains.append((host, port, tag))
        
        print(f"       有效节点行: {valid_lines} (IP: {len(nodes)}, 域名: {len(raw_domains)})")
        
    except Exception as e:
        print(f"       [!] 抓取失败: {e}")
        return set()

    # 批量解析域名
    if raw_domains:
        print(f"       正在解析 {len(raw_domains)} 个域名...", end="", flush=True)
        resolver = DNSResolver()
        unique_domains = {}
        for domain, port, tag in raw_domains:
            if domain not in unique_domains:
                unique_domains[domain] = []
            unique_domains[domain].append((port, tag))
        
        resolved = 0
        for domain, entries in unique_domains.items():
            ips = resolver.resolve_fast(domain)
            if ips:
                for ip in ips:
                    for port, tag in entries:
                        nodes.add((ip, port, tag))
                        resolved += 1
        
        print(f" ✓ {resolved} 个IP")

    print(f"       ✓ 汇总: {len(nodes)} 个IP节点")
    return nodes


def check_availability(ip, port, retries=2):
    """调用API检测节点可用性"""
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
        except Exception:
            if attempt < retries - 1:
                time.sleep(1)
    return False, "UN"


def tcp_ping(ip, port, timeout=3):
    """TCP延迟测试"""
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
    """多次ping取最小值"""
    results = []
    for _ in range(count):
        lat = tcp_ping(ip, port)
        if lat < 99999:
            results.append(lat)
        if _ < count - 1:
            time.sleep(0.1)
    return min(results) if results else 99999


def update_dns_record(record_name, ips):
    """更新Cloudflare DNS"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not record_name:
        return
    ips = sorted(set(ips))
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    try:
        print(f"[*] 更新域名: {record_name} (IP数: {len(ips)})")
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=10).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=10)
        for ip in ips:
            data = {"type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False}
            requests.post(base_url, headers=headers, json=data, timeout=10)
    except Exception as e:
        print(f"[!] DNS更新出错: {e}")


def get_region_domain(region_code):
    """获取地区DNS记录名"""
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
            return {"ip": ip, "port": port, "tag": tag, "latency": latency}
    return None


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("🚀 ProxyIP 节点收集工具 v3.2 (CF绕过)")
    print("=" * 60 + "\n")

    resolver = DNSResolver()
    domain_raw = {}
    sub_raw_data = set()

    print("[1/4] 📡 收集原始节点数据...\n")

    for src, source_type in SOURCES:
        if src.startswith("http"):
            print(f"  📥 [订阅] {src[:60]}")
            nodes = fetch_subscription(src)
            print(f"     汇总: {len(nodes)} 个IP节点\n")
            sub_raw_data.update(nodes)
        else:
            hint, _ = DOMAIN_REGION_HINT.get(src, ("UN", "LB"))
            print(f"  🌐 [域名] {src} (提示:{hint})")
            
            ips = set()
            for dns_server in PUBLIC_DNS_SERVERS:
                results = resolver.query_single_dns(src, dns_server, 'A', timeout=4)
                ips.update(results)
                if len(ips) >= 10:
                    break
            
            if source_type in ["LB", "MIXED"] and len(ips) > 0:
                for _ in range(5):
                    more = resolver.query_single_dns(src, "8.8.8.8", 'A', timeout=3)
                    ips.update(more)
            
            print(f"     解析到 {len(ips)} 个IP\n")
            domain_raw[src] = (ips, hint, source_type)

    domain_ip_meta = {}
    for domain, (ips, hint, stype) in domain_raw.items():
        for ip in ips:
            if ip not in domain_ip_meta:
                domain_ip_meta[ip] = (domain, hint, stype)

    total_domain = len(domain_ip_meta)
    total_sub = len(sub_raw_data)
    print("=" * 60)
    print(f"📊 待检测: 域名源={total_domain} IP, 订阅源={total_sub} IP")
    print("=" * 60 + "\n")

    print("[2/4] 🔍 检测域名源IP...\n")
    domain_verified = defaultdict(list)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(process_node, ip, "443", "UN"): ip for ip in domain_ip_meta.keys()}
        for i, future in enumerate(as_completed(futures)):
            res = future.result()
            if res:
                domain_verified[res["tag"]].append(res)
                print(f"  ✓ [{i+1}/{total_domain}] {res['ip']} | {res['tag']} | {res['latency']}ms")
    
    print(f"\n  域名源通过: {sum(len(v) for v in domain_verified.values())}/{total_domain}\n")

    print("[3/4] 🔍 检测订阅源IP...\n")
    sub_verified = defaultdict(list)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(process_node, ip, port, tag): (ip, port, tag) for ip, port, tag in sub_raw_data}
        for i, future in enumerate(as_completed(futures)):
            res = future.result()
            if res:
                sub_verified[res["tag"]].append(res)
                print(f"  ✓ [{i+1}/{total_sub}] {res['ip']}:{res['port']} | {res['tag']} | {res['latency']}ms")
    
    print(f"\n  订阅源通过: {sum(len(v) for v in sub_verified.values())}/{total_sub}\n")

    print("[4/4] 💾 输出结果...\n")
    
    print("  📌 Cloudflare DNS更新:")
    for region in sorted(ALLOWED_REGIONS):
        nodes = domain_verified.get(region, [])
        if nodes:
            top = sorted(nodes, key=lambda x: x["latency"])[:TOP_N]
            target = get_region_domain(region)
            if target:
                print(f"    {region}: {len(top)} 节点 → {target}")
                update_dns_record(target, [n["ip"] for n in top])
        else:
            print(f"    {region}: 无节点")

    domain_lines = [f"{n['ip']}#{n['tag']}" for r in domain_verified.values() for n in r]
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_lines)))
    
    other_lines = []
    for region in sorted(ALLOWED_REGIONS):
        nodes = sorted(sub_verified.get(region, []), key=lambda x: x["latency"])[:TOP_N]
        other_lines.extend([f"{n['ip']}:{n['port']}#{n['tag']}" for n in nodes])
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(other_lines))

    print(f"\n  ✓ domain_ips.txt: {len(domain_lines)} 行")
    print(f"  ✓ other_ips.txt: {len(other_lines)} 行")
    print("\n" + "=" * 60)
    print("✅ 完成!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
