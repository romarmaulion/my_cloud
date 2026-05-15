import requests
import base64
import json
import re
import socket
import dns.resolver
import os
import ipaddress
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 配置区域 =================

SOURCES = [
    # 域名源 (对应 domain_ips.txt，进行网段过滤)
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.SG.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("kr.william.us.ci", "DOMAIN"),
    # 订阅源 (对应 other_ips.txt，不进行网段过滤)
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

# 【仅针对 DOMAIN 源】的网段过滤配置，留空则不过滤
REGION_FILTERS = {
    "HK": ["219.0.0.0/8"], # 示例: ["103.0.0.0/8"]
    "TW": [],
    "KR": [],
    "US": [],
    "JP": [],
    "SG": [],
}

ALLOWED_REGIONS = set(REGION_FILTERS.keys())
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

# Cloudflare 配置
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID   = os.getenv("CF_ZONE_ID")
BASE_DOMAIN  = os.getenv("BASE_DOMAIN") # 必须设置，如 "example.com"

# ================= 核心函数 =================

def log(msg):
    print(msg, flush=True)

def is_ip_in_allowed_subnets(ip, region):
    subnets = REGION_FILTERS.get(region, [])
    if not subnets: return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in subnets:
            if ip_obj in ipaddress.ip_network(network, strict=False): return True
    except: pass
    return False

def resolve_domain(domain):
    ips = set()
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = 1
        answers = resolver.resolve(domain, 'A')
        for rdata in answers: ips.add(rdata.address)
    except:
        try: ips.add(socket.gethostbyname(domain))
        except: pass
    return ips

def safe_b64decode(data):
    if not data: return None
    data = re.sub(r'[^a-zA-Z0-9+/=]', '', data.strip())
    padding = 4 - len(data) % 4
    if padding != 4: data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except: return None

def check_region(ip, port):
    try:
        resp = requests.get(CHECK_API, params={"proxyip": f"{ip}:{port}"}, timeout=10).json()
        if resp.get("success"):
            return resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
    except: pass
    return "UN"

def update_cf_dns(region, ips):
    if not all([CF_API_TOKEN, CF_ZONE_ID, BASE_DOMAIN]): return
    
    # 直接拼接域名: hk.example.com
    record_name = f"{region.lower()}.{BASE_DOMAIN}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    try:
        # 1. 删除旧记录
        res = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=10).json()
        if res.get("success"):
            for rec in res.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=10)
        # 2. 写入新记录
        for ip in ips:
            requests.post(base_url, headers=headers, json={
                "type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False
            }, timeout=10)
        log(f"      [CF] {record_name} 已更新")
    except Exception as e:
        log(f"      [!] CF更新失败: {e}")

# ================= 主程序 =================

def main():
    if not BASE_DOMAIN:
        log("❌ 错误: 请先设置环境变量 BASE_DOMAIN")
        return

    log(f"🚀 开始运行 | 基础域名: {BASE_DOMAIN}")
    raw_candidates = set()

    # 1. 提取 IP
    for src, typ in SOURCES:
        if typ == "DOMAIN":
            for ip in resolve_domain(src): raw_candidates.add((ip, "443", "DOMAIN"))
        else:
            try:
                resp = requests.get(src, timeout=15)
                content = safe_b64decode(resp.text) or resp.text
                for line in content.splitlines():
                    if "://" in line:
                        body = line.split("#")[0]
                        after_proto = body.split("://", 1)[1]
                        if "@" in after_proto: after_proto = after_proto.rsplit("@", 1)[1]
                        host_port = after_proto.split("/")[0].split("?")[0]
                        h, p = host_port.split(":", 1) if ":" in host_port else (host_port, "443")
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                            raw_candidates.add((h, p, "SUB"))
                        else:
                            for ip in resolve_domain(h): raw_candidates.add((ip, p, "SUB"))
            except: continue

    log(f"📊 提取完成，共 {len(raw_candidates)} 个 IP 待检测")

    # 2. 地区验证与过滤
    verified_pools = { r: {"DOMAIN": [], "SUB": []} for r in ALLOWED_REGIONS }

    def process(ip, port, st):
        region = check_region(ip, port)
        if region in ALLOWED_REGIONS:
            if st == "DOMAIN":
                if is_ip_in_allowed_subnets(ip, region): return region, ip, port, st
            else:
                return region, ip, port, st
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(process, ip, port, st) for ip, port, st in raw_candidates]
        for f in as_completed(futures):
            res = f.result()
            if res:
                region, ip, port, st = res
                verified_pools[region][st].append((ip, port))

    # 3. 随机筛选与输出
    domain_final, sub_final = [], []

    for region in sorted(ALLOWED_REGIONS):
        log(f"\n🌍 地区: {region}")
        
        # 域名源: 筛选 -> 更新CF -> 存入列表
        d_pool = verified_pools[region]["DOMAIN"]
        d_select = random.sample(d_pool, min(len(d_pool), TOP_N))
        if d_select:
            update_cf_dns(region, [x[0] for x in d_select])
            for ip, port in d_select: domain_final.append(f"{ip}#{region}")
            log(f"   [域名源] 随机抽取 {len(d_select)} 个")

        # 订阅源: 筛选 -> 存入列表
        s_pool = verified_pools[region]["SUB"]
        s_select = random.sample(s_pool, min(len(s_pool), TOP_N))
        if s_select:
            for ip, port in s_select: sub_final.append(f"{ip}:{port}#{region}")
            log(f"   [订阅源] 随机抽取 {len(s_select)} 个")

    # 4. 写入文件
    with open("domain_ips.txt", "w") as f: f.write("\n".join(domain_final))
    with open("other_ips.txt", "w") as f: f.write("\n".join(sub_final))
    
    log("\n" + "="*50)
    log(f"✅ 任务完成！记录总数: domain_ips({len(domain_final)}), other_ips({len(sub_final)})")

if __name__ == "__main__":
    main()
