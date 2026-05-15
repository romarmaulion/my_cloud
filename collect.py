import requests
import base64
import json
import re
import socket
import dns.resolver
import time
import os
import subprocess
import ipaddress
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ================= 配置区域 =================

SOURCES = [
    # 域名源
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.SG.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("kr.william.us.ci", "DOMAIN"),
    # 订阅源
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

# 地区过滤与自定义网段配置
# 如果某个地区的列表为空 []，则表示该地区不过滤网段
REGION_FILTERS = {
    "HK": ["219.0.0.0/8"], # 示例网段
    "SG": [], 
    "US": [],
    "JP": [],
    "KR": [],
    "TW": []
}

ALLOWED_REGIONS = set(REGION_FILTERS.keys())
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
CF_ZONE_ID     = os.getenv("CF_ZONE_ID")
BASE_DOMAIN    = os.getenv("BASE_DOMAIN")

CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "SG": os.getenv("CF_RECORD_SG"),
    "US": os.getenv("CF_RECORD_US"),
    "JP": os.getenv("CF_RECORD_JP"),
    "KR": os.getenv("CF_RECORD_KR"),
}

PUBLIC_DNS = [
    "8.8.8.8", "1.1.1.1", "114.114.114.114", "119.29.29.29"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "v2rayNG/1.8.19",
]

# ================= 核心工具函数 =================

def log(msg):
    print(msg, flush=True)

def is_ip_in_allowed_subnets(ip, region):
    """检查 IP 是否在定义的网段内"""
    subnets = REGION_FILTERS.get(region, [])
    if not subnets:
        return True # 如果未定义网段，默认允许所有
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in subnets:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True
    except Exception as e:
        pass
    return False

def resolve_domain_extreme(domain):
    """极速解析域名"""
    ips = set()
    resolver = dns.resolver.Resolver(configure=False)
    for dns_server in PUBLIC_DNS:
        resolver.nameservers = [dns_server]
        resolver.timeout = 1
        resolver.lifetime = 1
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
    if not data: return None
    data = re.sub(r'[^a-zA-Z0-9+/=]', '', data.strip())
    padding = 4 - len(data) % 4
    if padding != 4: data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None

def fetch_subscription_extreme(url):
    """获取订阅内容"""
    try:
        resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return None

def parse_node_link(line):
    line = line.strip()
    if not line: return None
    if line.startswith("vmess://"):
        try:
            decoded = safe_b64decode(line[8:])
            obj = json.loads(decoded)
            return obj.get("add"), str(obj.get("port", "443"))
        except: pass
    elif "://" in line:
        try:
            body = line.split("#")[0]
            after_proto = body.split("://", 1)[1]
            if "@" in after_proto: after_proto = after_proto.rsplit("@", 1)[1]
            host_port = after_proto.split("/")[0].split("?")[0]
            if ":" in host_port:
                h, p = host_port.split(":", 1)
                return h, p
            return host_port, "443"
        except: pass
    return None

def check_node_region(ip, port):
    """仅检测地区，不测速"""
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=10
        ).json()
        if resp.get("success") is True:
            return resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
    except:
        pass
    return "UN"

def update_cloudflare_dns(region, ips):
    if not CF_API_TOKEN or not CF_ZONE_ID or not ips: return
    record_name = CUSTOM_DOMAIN_MAP.get(region) or (f"{region.lower()}.{BASE_DOMAIN}" if BASE_DOMAIN else None)
    if not record_name: return

    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    
    try:
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=10).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=10)
        for ip in ips:
            requests.post(base_url, headers=headers, json={"type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False}, timeout=10)
        log(f"      [CF] {record_name} 已随机更新为 {len(ips)} 个 IP")
    except Exception as e:
        log(f"      [!] DNS 更新异常: {e}")

# ================= 主流程 =================

def main():
    log("🚀 [节点提取与随机筛选工具 v5.0] 开始运行")
    
    raw_candidates = set() # (ip, port, source_type)

    # 阶段 1: 提取
    for src, typ in SOURCES:
        if typ == "DOMAIN":
            for ip in resolve_domain_extreme(src):
                raw_candidates.add((ip, "443", "DOMAIN"))
        elif typ == "SUB":
            content = fetch_subscription_extreme(src)
            if not content: continue
            decoded = safe_b64decode(content) or content
            for line in decoded.splitlines():
                parsed = parse_node_link(line)
                if parsed:
                    h, p = parsed
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                        raw_candidates.add((h, p, "SUB"))
                    else:
                        for ip in resolve_domain_extreme(h):
                            raw_candidates.add((ip, p, "SUB"))

    log(f"📊 初始采集到 {len(raw_candidates)} 个 IP，开始地区验证与网段过滤...")

    # 阶段 2: 验证与网段过滤
    # 结果归类: verified_pools[region][source_type] = [ (ip, port), ... ]
    verified_pools = { r: {"DOMAIN": [], "SUB": []} for r in ALLOWED_REGIONS }

    def process_task(ip, port, st):
        region = check_node_region(ip, port)
        if region in ALLOWED_REGIONS:
            if is_ip_in_allowed_subnets(ip, region):
                return region, ip, port, st
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(process_task, ip, port, st) for ip, port, st in raw_candidates]
        for future in as_completed(futures):
            res = future.result()
            if res:
                region, ip, port, st = res
                verified_pools[region][st].append((ip, port))

    # 阶段 3: 随机选取并输出
    domain_output = []
    sub_output = []

    for region in ALLOWED_REGIONS:
        log(f"\n🌍 地区: {region}")
        
        # 1. 域名源随机选取
        d_pool = verified_pools[region]["DOMAIN"]
        d_select = random.sample(d_pool, min(len(d_pool), TOP_N))
        if d_select:
            update_cloudflare_dns(region, [x[0] for x in d_select])
            for ip, port in d_select:
                domain_output.append(f"{ip}#{region}")
            log(f"   [域名源] 随机选取: {[x[0] for x in d_select]}")

        # 2. 订阅源随机选取
        s_pool = verified_pools[region]["SUB"]
        s_select = random.sample(s_pool, min(len(s_pool), TOP_N))
        if s_select:
            for ip, port in s_select:
                sub_output.append(f"{ip}:{port}#{region}")
            log(f"   [订阅源] 随机选取: {[f'{x[0]}:{x[1]}' for x in s_select]}")

    with open("domain_ips.txt", "w") as f: f.write("\n".join(domain_output))
    with open("other_ips.txt", "w") as f: f.write("\n".join(sub_output))
    
    log("\n" + "="*50)
    log("🎉 任务完成！IP 已随机抽取并过滤网段。")
    log(f"写入 domain_ips.txt: {len(domain_output)} 行")
    log(f"写入 other_ips.txt: {len(sub_output)} 行")

if __name__ == "__main__":
    main()
