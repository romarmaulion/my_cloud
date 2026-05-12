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

# ================= Session 优化（关键） =================
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=100,
    pool_maxsize=100,
    max_retries=2,
)
session.mount("http://", adapter)
session.mount("https://", adapter)

# ================= 配置 =================
SOURCES = [
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.JP.CMLiussss.net",
    "sjc.o00o.ooo",
    "tw.william.us.ci",
    "proxy.xinyitang.dpdns.org",
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://sub.cmliussss.net/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://owo.o00o.ooo/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
    "https://cm.soso.edu.kg/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F",
]

DOMAIN_REGION_HINT = {
    "ProxyIP.HK.CMLiussss.net": "HK",
    "ProxyIP.JP.CMLiussss.net": "JP",
    "sjc.o00o.ooo": "US",
    "tw.william.us.ci": "TW",
    "proxy.xinyitang.dpdns.org": "HK",
}

PUBLIC_DNS_SERVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
]

CHECK_API = "https://api.090227.xyz/check"

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5

# ================= 工具 =================

def extract_country_local(label):
    label = label.upper()
    cn_map = {"香港": "HK", "日本": "JP", "新加坡": "SG", "台湾": "TW", "美國": "US"}
    for k, v in cn_map.items():
        if k in label:
            return v
    en_map = {
        "HK": "HK", "JP": "JP", "SG": "SG",
        "TW": "TW", "US": "US", "USA": "US"
    }
    for k, v in en_map.items():
        if k in label:
            return v
    return "UN"


# ================= DNS 核心增强版 =================

def resolve_domain_all_ips(domain):
    ips = set()

    # 1 socket fallback（非常重要）
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.add(ip)
    except:
        pass

    # 2 并发 DNS
    def query_dns(dns_server):
        result = set()
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [dns_server]
            r.timeout = 3
            r.lifetime = 5

            answers = r.resolve(domain, "A")
            for a in answers:
                result.add(a.address)
        except:
            pass
        return result

    with ThreadPoolExecutor(max_workers=16) as ex:
        futures = [ex.submit(query_dns, d) for d in PUBLIC_DNS_SERVERS]
        for f in as_completed(futures):
            ips.update(f.result())

    # 3 DoH fallback
    doh = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/resolve",
    ]

    for url in doh:
        try:
            resp = session.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=5,
            ).json()

            for ans in resp.get("Answer", []):
                ip = ans.get("data")
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip)):
                    ips.add(ip)
        except:
            pass

    return ips


# ================= TCP 检测 =================

def tcp_ping(ip, port):
    start = time.time()
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, int(port)))
        s.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999


def multi_ping(ip, port):
    vals = []
    for _ in range(3):
        v = tcp_ping(ip, port)
        if v < 99999:
            vals.append(v)
    return min(vals) if vals else 99999


# ================= 可用性检测 =================

def check_availability(ip, port):
    try:
        r = session.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=12,
        ).json()

        if r.get("success"):
            region = r.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN")
            return True, region.upper()
    except:
        pass
    return False, "UN"


# ================= 订阅解析（已修复漏 IP） =================

def fetch_subscription(url):
    nodes = set()
    try:
        content = session.get(url, timeout=20).text

        try:
            decoded = base64.b64decode(content + "=" * (-len(content) % 4)).decode()
        except:
            decoded = content

        for line in decoded.splitlines():
            addr, port, tag = "", "443", "UN"

            # vmess
            if line.startswith("vmess://"):
                try:
                    v = json.loads(base64.b64decode(line[8:] + "==").decode())
                    addr = v.get("add", "")
                    port = str(v.get("port", 443))
                    tag = extract_country_local(v.get("ps", ""))
                except:
                    pass

            # vless/trojan
            elif "@" in line:
                m = re.search(r'@([^:@\s]+):(\d+)', line)
                if m:
                    addr, port = m.group(1), m.group(2)
                    tag = extract_country_local(line)

            # raw
            else:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?', line)
                if m:
                    addr, port = m.group(1), m.group(2) or "443"
                    tag = extract_country_local(line)

            # ⭐关键修复：域名也解析
            if addr:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                    nodes.add((addr, port, tag))
                else:
                    for ip in resolve_domain_all_ips(addr):
                        nodes.add((ip, port, tag))

    except:
        pass

    return nodes


# ================= 节点处理 =================

def process_node(ip, port, tag):
    ok, real = check_availability(ip, port)
    final_tag = real if real != "UN" else tag

    if not ok:
        return None

    lat = multi_ping(ip, port)
    if lat > 2000:
        return None

    return {
        "ip": ip,
        "port": port,
        "tag": final_tag,
        "latency": lat
    }


# ================= 主流程 =================

def main():

    domain_ips = {}
    sub_nodes = set()

    print("[1] 收集数据...")

    for s in SOURCES:
        if s.startswith("http"):
            sub_nodes.update(fetch_subscription(s))
        else:
            ips = resolve_domain_all_ips(s)
            domain_ips[s] = ips

    print("[2] 并发检测域名IP...")

    all_domain_nodes = {}
    for domain, ips in domain_ips.items():
        hint = DOMAIN_REGION_HINT.get(domain, "UN")

        with ThreadPoolExecutor(max_workers=64) as ex:
            futures = [ex.submit(process_node, ip, 443, hint) for ip in ips]

            for f in as_completed(futures):
                r = f.result()
                if r:
                    all_domain_nodes.setdefault(r["tag"], []).append(r)

    print("[3] 检测订阅节点...")

    all_sub_nodes = {}

    with ThreadPoolExecutor(max_workers=64) as ex:
        futures = [ex.submit(process_node, ip, port, tag) for ip, port, tag in sub_nodes]

        for f in as_completed(futures):
            r = f.result()
            if r:
                all_sub_nodes.setdefault(r["tag"], []).append(r)

    print("[4] 输出结果...")

    for region in ALLOWED_REGIONS:
        nodes = sorted(all_domain_nodes.get(region, []), key=lambda x: x["latency"])[:TOP_N]
        print(region, len(nodes))

    print("完成")


if __name__ == "__main__":
    main()
