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
    # 域名
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("proxy.xinyitang.dpdns.org", "DOMAIN"),

    # 订阅
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
CF_ZONE_ID     = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)


def safe_b64decode(data):
    try:
        data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None


def resolve_domain(domain):
    """解析域名为IP"""
    ips = set()
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, "A")
        for r in answers:
            ips.add(r.address)
    except:
        pass

    if not ips:
        try:
            ips.add(socket.gethostbyname(domain))
        except:
            pass

    return ips


def extract_host_port(line):
    """从节点链接中提取 host:port"""
    if line.startswith("vmess://"):
        decoded = safe_b64decode(line[8:])
        if not decoded:
            return None
        try:
            obj = json.loads(decoded)
            return obj.get("add"), str(obj.get("port", "443"))
        except:
            return None

    if "://" in line:
        body = line.split("://", 1)[1]
        if "@" in body:
            body = body.split("@", 1)[1]
        body = body.split("/")[0].split("?")[0]
        if ":" in body:
            host, port = body.split(":", 1)
        else:
            host, port = body, "443"
        return host, port

    return None


def fetch_subscription(url):
    """获取订阅"""
    nodes = set()
    try:
        headers = {"User-Agent": "v2rayNG/1.8.5"}
        resp = requests.get(url, headers=headers, timeout=20)
        content = resp.text

        if "Just a moment" in content:
            log("⚠️  被 Cloudflare 拦截")
            return set()

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
        log(f"订阅获取失败: {e}")

    return nodes


def check_node(ip, port):
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=15
        ).json()

        if resp.get("success"):
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

    return None


def tcp_latency(ip, port):
    start = time.time()
    try:
        sock = socket.create_connection((ip, int(port)), timeout=3)
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999


# ================= 主流程 =================

def main():
    log("🚀 开始收集节点")

    raw_nodes = set()

    # 收集阶段
    for src, typ in SOURCES:
        if typ == "DOMAIN":
            log(f"🌐 解析域名: {src}")
            ips = resolve_domain(src)
            for ip in ips:
                raw_nodes.add((ip, "443"))

        elif typ == "SUB":
            log(f"📥 获取订阅: {src[:50]}")
            nodes = fetch_subscription(src)
            raw_nodes.update(nodes)

    log(f"✅ 共收集 {len(raw_nodes)} 个节点，开始检测...")

    verified = defaultdict(list)

    # 检测阶段
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(check_node, ip, port): (ip, port)
            for ip, port in raw_nodes
        }

        for future in as_completed(futures):
            ip, port = futures[future]
            region = future.result()

            if region in ALLOWED_REGIONS:
                latency = tcp_latency(ip, port)
                if latency < 2000:
                    verified[region].append({
                        "ip": ip,
                        "port": port,
                        "latency": latency
                    })
                    log(f"✅ {ip}:{port} {region} {latency}ms")

    # 输出文件
    domain_lines = []
    for region in ALLOWED_REGIONS:
        nodes = sorted(verified[region], key=lambda x: x["latency"])[:TOP_N]
        for n in nodes:
            domain_lines.append(f"{n['ip']}#{region}")

    with open("domain_ips.txt", "w") as f:
        f.write("\n".join(domain_lines))

    log(f"✅ 输出完成，共 {len(domain_lines)} 个优选节点")


if __name__ == "__main__":
    main()
