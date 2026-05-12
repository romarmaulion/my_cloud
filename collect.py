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

# ================= 配置 =================

SOURCES = [
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("proxy.xinyitang.dpdns.org", "DOMAIN"),

    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=xxx&path=/", "SUB"),
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "JP": os.getenv("CF_RECORD_JP"),
    "US": os.getenv("CF_RECORD_US"),
    "SG": os.getenv("CF_RECORD_SG"),
    "TW": os.getenv("CF_RECORD_TW"),
}

# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)


def resolve_domain(domain):
    ips = set()
    log(f"🌐 解析域名: {domain}")
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "A")
        for r in answers:
            ips.add(r.address)
    except:
        pass

    for ip in ips:
        log(f"   ↳ {ip}")

    return ips


def safe_b64decode(data):
    try:
        data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None


def extract_host_port(line):
    if line.startswith("vmess://"):
        decoded = safe_b64decode(line[8:])
        if not decoded:
            return None
        obj = json.loads(decoded)
        return obj.get("add"), str(obj.get("port", "443"))

    if "://" in line:
        body = line.split("://", 1)[1]
        if "@" in body:
            body = body.split("@", 1)[1]
        body = body.split("/")[0].split("?")[0]
        if ":" in body:
            return body.split(":", 1)
        return body, "443"

    return None


def fetch_subscription(url):
    nodes = set()
    log(f"📥 订阅: {url[:60]}")
    try:
        resp = requests.get(url, timeout=20)
        content = resp.text
        decoded = safe_b64decode(content)
        lines = decoded.splitlines() if decoded else content.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            parsed = extract_host_port(line)
            if not parsed:
                continue

            host, port = parsed

            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                nodes.add((host, port))
            else:
                ips = resolve_domain(host)
                for ip in ips:
                    nodes.add((ip, port))

    except Exception as e:
        log(f"订阅失败: {e}")

    return nodes


def check_node(ip, port):
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=15
        ).json()

        if resp.get("success"):
            return (
                resp.get("probe_results", {})
                .get("ipv4", {})
                .get("exit", {})
                .get("country", "UN")
                .upper()
            )
    except:
        pass
    return None


def tcp_latency(ip, port):
    start = time.time()
    try:
        sock = socket.create_connection((ip, int(port)), timeout=3)
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999


def update_dns(region, ips):
    if not CF_API_TOKEN or not CF_ZONE_ID:
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

    log(f"🌍 更新 {record_name} → {ips}")

    # 删除旧记录
    resp = requests.get(base_url, headers=headers, params={"name": record_name}).json()
    if resp.get("success"):
        for rec in resp.get("result", []):
            requests.delete(f"{base_url}/{rec['id']}", headers=headers)

    # 添加新记录
    for ip in ips:
        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": 60,
            "proxied": False
        }
        requests.post(base_url, headers=headers, json=data)


# ================= 主流程 =================

def main():
    domain_nodes = set()
    sub_nodes = set()

    for src, typ in SOURCES:
        if typ == "DOMAIN":
            ips = resolve_domain(src)
            for ip in ips:
                domain_nodes.add((ip, "443"))

        if typ == "SUB":
            sub_nodes.update(fetch_subscription(src))

    verified_domain = defaultdict(list)
    verified_sub = defaultdict(list)

    all_nodes = [(ip, port, "DOMAIN") for ip, port in domain_nodes] + \
                [(ip, port, "SUB") for ip, port in sub_nodes]

    log("\n🔍 开始检测...\n")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(check_node, ip, port): (ip, port, st)
            for ip, port, st in all_nodes
        }

        for future in as_completed(futures):
            ip, port, st = futures[future]
            region = future.result()

            if region in ALLOWED_REGIONS:
                latency = tcp_latency(ip, port)
                if latency < 2000:
                    log(f"✅ {ip}:{port} {region} {latency}ms 来源:{st}")
                    if st == "DOMAIN":
                        verified_domain[region].append((ip, latency))
                    else:
                        verified_sub[region].append((ip, port, latency))

    # 更新CF
    for region in ALLOWED_REGIONS:
        nodes = sorted(verified_domain[region], key=lambda x: x[1])[:TOP_N]
        update_dns(region, [ip for ip, _ in nodes])

    # 写文件
    with open("domain_ips.txt", "w") as f:
        for region in ALLOWED_REGIONS:
            for ip, latency in verified_domain[region]:
                f.write(f"{ip}#{region}\n")

    with open("other_ips.txt", "w") as f:
        for region in ALLOWED_REGIONS:
            for ip, port, latency in verified_sub[region]:
                f.write(f"{ip}:{port}#{region}\n")

    log("\n✅ 完成")


if __name__ == "__main__":
    main()
