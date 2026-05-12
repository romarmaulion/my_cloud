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

# ================= 配置区域 =================
SOURCES = [
    # 域名类（DNS解析）
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.JP.CMLiussss.net",   # ← 原来这里缺逗号，导致和下一行拼接！
    "sjc.o00o.ooo",
    "tw.william.us.ci",
    "proxy.xinyitang.dpdns.org",  # ← 这里也缺逗号
    # 订阅链接类（HTTP请求）
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://sub.cmliussss.net/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://owo.o00o.ooo/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://cm.soso.edu.kg/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
]

# 域名源与预期地区映射（DNS解析时使用，避免全部默认HK）
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

# 从 GitHub Secrets 获取环境变量
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

# DNS查询使用的公共服务器（多个，提高成功率）
PUBLIC_DNS_SERVERS = [
    "8.8.8.8",        # Google
    "1.1.1.1",        # Cloudflare
    "208.67.222.222", # OpenDNS
    "9.9.9.9",        # Quad9
]
# ===========================================

def extract_country_local(label):
    """从节点标签提取国家代码"""
    label = label.upper()
    # 处理旗帜 emoji
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first  = ord(emoji_chars[0]) - 0x1F1E6
        second = ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    # 中文关键词映射
    cn_map = {
        "香港": "HK", "日本": "JP", "新加坡": "SG",
        "台湾": "TW", "台灣": "TW", "美国": "US", "美國": "US",
    }
    for name, code in cn_map.items():
        if name in label:
            return code
    # 英文关键词映射
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

def resolve_domain_all_ips(domain):
    """
    多DNS服务器 + 多记录类型解析，尽可能获取所有IP
    返回: set of IPv4 strings
    """
    ips = set()

    # ---------- 方法1: 用系统/公共DNS解析A记录 ----------
    for dns_server in PUBLIC_DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.add(rdata.address)
        except Exception:
            pass

    # ---------- 方法2: 追踪CNAME链后再解析 ----------
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 10
        # resolve() 会自动跟随CNAME，但也单独尝试CNAME展开
        cname_target = domain
        for _ in range(5):  # 最多跟5层CNAME
            try:
                cname_ans = resolver.resolve(cname_target, 'CNAME')
                cname_target = str(cname_ans[0].target).rstrip('.')
            except Exception:
                break
        if cname_target != domain:
            # 对CNAME最终目标再做A记录解析
            for dns_server in PUBLIC_DNS_SERVERS:
                try:
                    r2 = dns.resolver.Resolver(configure=False)
                    r2.nameservers = [dns_server]
                    r2.timeout = 5
                    r2.lifetime = 8
                    for rdata in r2.resolve(cname_target, 'A'):
                        ips.add(rdata.address)
                except Exception:
                    pass
    except Exception:
        pass

    # ---------- 方法3: 用 requests 通过 DNS-over-HTTPS 查询 ----------
    doh_urls = [
        f"https://dns.google/resolve?name={domain}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
    ]
    for url in doh_urls:
        try:
            resp = requests.get(
                url,
                headers={"accept": "application/dns-json"},
                timeout=8,
            ).json()
            for answer in resp.get("Answer", []):
                data = answer.get("data", "")
                # type=1 是A记录
                if answer.get("type") == 1 and re.match(r'^\d+\.\d+\.\d+\.\d+$', data):
                    ips.add(data)
        except Exception:
            pass

    return ips


def check_availability(ip, port):
    """调用在线API检测节点可用性，返回 (is_ok, region)"""
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=15,
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
        pass
    return False, "UN"


def tcp_ping(ip, port, timeout=3):
    """TCP握手延迟测试，单位毫秒"""
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
    """多次TCP ping取最小值，减少偶发抖动干扰"""
    results = []
    for _ in range(count):
        lat = tcp_ping(ip, port)
        if lat < 99999:
            results.append(lat)
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
        # 删除旧记录
        get_resp = requests.get(
            base_url, headers=headers, params={"name": record_name}
        ).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                del_resp = requests.delete(f"{base_url}/{rec['id']}", headers=headers).json()
                if not del_resp.get("success"):
                    print(f"  [!] 删除旧记录失败: {rec['id']}")
        # 写入新记录
        for ip in ips:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False,
            }
            post_resp = requests.post(base_url, headers=headers, json=data).json()
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
    """
    检测单个节点：可用性 → 真实地区 → 延迟
    返回节点信息字典或 None
    """
    is_ok, real_region = check_availability(ip, port)
    # 优先使用API返回的真实地区，其次用标签提示
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
    """
    抓取订阅链接，解析出 (ip, port, tag) 三元组集合
    支持 vmess / vless / trojan / ss / hy2 等格式
    """
    nodes = set()
    try:
        headers = {
            "User-Agent": "v2rayNG/1.8.5",
            "Accept": "*/*",
        }
        content = requests.get(url, headers=headers, timeout=20).text

        # 尝试 base64 解码
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

            # ---------- vmess ----------
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

            # ---------- vless / trojan / ss / hysteria2 ----------
            elif "://" in line and "@" in line:
                match = re.search(r'@([^:@\s]+):(\d+)', line)
                if match:
                    addr = match.group(1)
                    port = match.group(2)
                    label = line.split("#")[-1] if "#" in line else line
                    tag = extract_country_local(label)

            # ---------- 纯 IP:port 行 ----------
            else:
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?', line)
                if match:
                    addr = match.group(1)
                    port = match.group(2) if match.group(2) else "443"
                    label = line.split("#")[-1] if "#" in line else line
                    tag = extract_country_local(label)

            # 只接受纯IPv4，过滤域名地址
            if addr and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', addr):
                nodes.add((addr, str(port), tag))

    except Exception as e:
        print(f"  [!] 订阅抓取失败 {url}: {e}")

    return nodes


def main():
    domain_raw: dict[str, set] = {}  # domain -> set of IPs
    sub_raw_data: set = set()

    # ===== 第一步：收集原始数据 =====
    print("=" * 50)
    print("[1/4] 正在收集原始节点数据...")
    print("=" * 50)

    for src in SOURCES:
        if src.startswith("http"):
            print(f"  [订阅] {src[:60]}...")
            nodes = fetch_subscription(src)
            print(f"         解析到 {len(nodes)} 个节点")
            sub_raw_data.update(nodes)
        else:
            print(f"  [域名] {src}")
            ips = resolve_domain_all_ips(src)
            print(f"         解析到 {len(ips)} 个IP: {ips}")
            domain_raw[src] = ips

    # 汇总所有域名解析出的IP（去重），并附带地区提示
    domain_ip_hint: dict[str, str] = {}   # ip -> region_hint
    for domain, ips in domain_raw.items():
        hint = DOMAIN_REGION_HINT.get(domain, "UN")
        for ip in ips:
            # 若同一IP来自多个域名，保留最具体的提示
            if ip not in domain_ip_hint or domain_ip_hint[ip] == "UN":
                domain_ip_hint[ip] = hint

    print(f"\n  汇总：域名源共 {len(domain_ip_hint)} 个去重IP，订阅源共 {len(sub_raw_data)} 个节点\n")

    # ===== 第二步：并发检测域名IP =====
    print("=" * 50)
    print(f"[2/4] 正在检测域名源 {len(domain_ip_hint)} 个IP...")
    print("=" * 50)

    domain_verified_groups: dict[str, list] = defaultdict(list)

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(process_node, ip, "443", hint): ip
            for ip, hint in domain_ip_hint.items()
        }
        for future in as_completed(future_map):
            res = future.result()
            if res:
                domain_verified_groups[res["tag"]].append(res)
                print(f"  [✓] {res['ip']}:{res['port']} | {res['tag']} | {res['latency']}ms")

    total_domain_ok = sum(len(v) for v in domain_verified_groups.values())
    print(f"\n  域名源有效节点: {total_domain_ok} 个\n")

    # ===== 第三步：并发检测订阅IP =====
    print("=" * 50)
    print(f"[3/4] 正在检测订阅源 {len(sub_raw_data)} 个节点...")
    print("=" * 50)

    sub_verified_groups: dict[str, list] = defaultdict(list)

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(process_node, ip, port, tag): (ip, port, tag)
            for ip, port, tag in sub_raw_data
        }
        for future in as_completed(future_map):
            res = future.result()
            if res:
                sub_verified_groups[res["tag"]].append(res)
                print(f"  [✓] {res['ip']}:{res['port']} | {res['tag']} | {res['latency']}ms")

    total_sub_ok = sum(len(v) for v in sub_verified_groups.values())
    print(f"\n  订阅源有效节点: {total_sub_ok} 个\n")

    # ===== 第四步：输出结果 =====
    print("=" * 50)
    print("[4/4] 正在输出结果...")
    print("=" * 50)

    # 4-A: 更新 Cloudflare DNS（仅域名源）
    print("\n[*] 同步域名解析结果到 Cloudflare DNS...")
    for region in ALLOWED_REGIONS:
        nodes = domain_verified_groups.get(region, [])
        if nodes:
            sorted_nodes = sorted(nodes, key=lambda x: x["latency"])[:TOP_N]
            target_domain = get_region_domain(region)
            if target_domain:
                update_dns_record(target_domain, [n["ip"] for n in sorted_nodes])
            print(f"  [+] {region}: {len(sorted_nodes)} 个节点 -> {target_domain}")
        else:
            print(f"  [-] {region} (域名源): 无可用节点，跳过 DNS 更新")

    # 4-B: 保存 domain_ips.txt（全部通过的域名源节点）
    domain_out_lines = []
    for region in ALLOWED_REGIONS:
        for n in sorted(domain_verified_groups.get(region, []), key=lambda x: x["latency"]):
            domain_out_lines.append(f"{n['ip']}#{n['tag']}  {n['latency']}ms")

    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(domain_out_lines))
    print(f"\n  已写入 domain_ips.txt ({len(domain_out_lines)} 行)")

    # 4-C: 保存 other_ips.txt（订阅源 Top N）
    other_out_lines = []
    for region in ALLOWED_REGIONS:
        nodes = sorted(sub_verified_groups.get(region, []), key=lambda x: x["latency"])[:TOP_N]
        for n in nodes:
            other_out_lines.append(f"{n['ip']}:{n['port']}#{n['tag']}  {n['latency']}ms")

    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(other_out_lines))
    print(f"  已写入 other_ips.txt ({len(other_out_lines)} 行)")

    # 4-D: 汇总统计
    print("\n" + "=" * 50)
    print("汇总统计")
    print("=" * 50)
    for region in sorted(ALLOWED_REGIONS):
        d = len(domain_verified_groups.get(region, []))
        s = len(sub_verified_groups.get(region, []))
        print(f"  {region}: 域名源={d}  订阅源={s}")


if __name__ == "__main__":
    main()
