import requests
import base64
import json
import re
import socket
import dns.resolver
import time
import os
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# ================= 配置区域 =================
SOURCES = [
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.JP.CMLiussss.net"
    "sjc.o00o.ooo",
    "tw.william.us.ci",
    "proxy.xinyitang.dpdns.org"
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://sub.cmliussss.net/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://owo.o00o.ooo/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://cm.soso.edu.kg/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" 
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 10
CHECK_API = "https://api.090227.xyz/check"

# 从 GitHub Secrets 获取环境变量
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN") # 基础域名，如 abc.com

# 可选：特定地区使用不同域名
CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "SG": os.getenv("CF_RECORD_SG"),
    "US": os.getenv("CF_RECORD_US"),
    "JP": os.getenv("CF_RECORD_JP"),
    "TW": os.getenv("CF_RECORD_TW")
}
# ===========================================

def extract_country_local(label):
    label = label.upper()
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first, second = ord(emoji_chars[0]) - 0x1F1E6, ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    cn_map = {"香港": "HK", "日本": "JP", "新加坡": "SG", "台湾": "TW", "美国": "US"}
    for name, code in cn_map.items():
        if name in label: return code
    return "UN"

def check_availability(ip, port):
    try:
        resp = requests.get(CHECK_API, params={"proxyip": f"{ip}:{port}"}, timeout=10).json()
        if resp.get("success") is True:
            region = resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
            return True, region
    except: pass
    return False, "UN"

def tcp_ping(ip, port):
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, int(port)))
        sock.close()
        return int((time.time() - start) * 1000)
    except: return 99999

def update_dns_record(record_name, ips):
    if not CF_API_TOKEN or not CF_ZONE_ID or not record_name:
        return
    ips = sorted(list(set(ips))) 
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    try:
        print(f"[*] 正在更新域名: {record_name} (IP数: {len(ips)})")
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}).json()
        if get_resp.get("success"):
            for rec in get_resp.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers)
        for ip in ips:
            data = {"type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False}
            requests.post(base_url, headers=headers, json=data)
    except Exception as e:
        print(f"[!] DNS更新出错: {e}")

def get_region_domain(region_code):
    if region_code in CUSTOM_DOMAIN_MAP and CUSTOM_DOMAIN_MAP[region_code]:
        return CUSTOM_DOMAIN_MAP[region_code]
    if CF_BASE_DOMAIN:
        return f"{region_code.lower()}.{CF_BASE_DOMAIN}"
    return None

def process_node(ip, port, initial_tag):
    is_ok, real_region = check_availability(ip, port)
    tag = real_region if real_region != "UN" else initial_tag
    if is_ok and tag in ALLOWED_REGIONS:
        latency = tcp_ping(ip, port)
        if latency < 2000:
            return {"ip": ip, "port": port, "tag": tag, "latency": latency}
    return None

def main():
    sub_raw_data = set() 
    domain_raw_ips = set()

    for src in SOURCES:
        if src.startswith("http"):
            try:
                headers = {'User-Agent': 'v2rayNG/1.8.5'}
                content = requests.get(src, headers=headers, timeout=15).text
                try: decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
                except: decoded = content
                for line in decoded.splitlines():
                    addr, port, tag = "", "443", "UN"
                    if "vmess://" in line:
                        v2 = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                        addr, port, tag = v2.get("add"), v2.get("port", "443"), extract_country_local(v2.get("ps", ""))
                    elif "@" in line:
                        match = re.search(r'@(.*?):(\d+)', line)
                        if match: 
                            addr, port = match.group(1), match.group(2)
                            tag = extract_country_local(line.split("#")[-1] if "#" in line else "UN")
                    else:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?', line)
                        if match: 
                            addr, port = match.group(1), match.group(2) if match.group(2) else "443"
                            tag = extract_country_local(line.split("#")[-1] if "#" in line else "UN")
                    if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                        sub_raw_data.add((addr, port, tag))
            except: pass
        else:
            try:
                for rdata in dns.resolver.resolve(src, 'A'):
                    domain_raw_ips.add(rdata.address)
            except: pass

    # 管道 A：域名解析出的 IP (-> DNS + 文件)
    print(f"[*] 正在筛选域名解析出的 {len(domain_raw_ips)} 个 IP...")
    domain_verified_groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, "443", "HK") for ip in domain_raw_ips]
        for f in futures:
            res = f.result()
            if res: domain_verified_groups[res['tag']].append(res)

    # 管道 B：订阅链接出的 IP (-> 仅文件)
    print(f"[*] 正在筛选订阅来源的 {len(sub_raw_data)} 个节点...")
    sub_verified_groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, port, tag) for ip, port, tag in sub_raw_data]
        for f in futures:
            res = f.result()
            if res: sub_verified_groups[res['tag']].append(res)

    # 更新 DNS (仅使用管道 A)
    print("\n[*] 正在同步域名解析结果到 Cloudflare DNS...")
    for region in ALLOWED_REGIONS:
        nodes = domain_verified_groups.get(region, [])
        if nodes:
            sorted_nodes = sorted(nodes, key=lambda x: x['latency'])[:TOP_N]
            target_domain = get_region_domain(region)
            if target_domain:
                update_dns_record(target_domain, [n['ip'] for n in sorted_nodes])
        else:
            print(f"[-] {region} (域名源): 无可用节点，跳过 DNS")

    # 保存 domain_ips.txt
    domain_out = [f"{n['ip']}#{n['tag']}" for r in domain_verified_groups.values() for n in r]
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_out)))

    # 保存 other_ips.txt
    other_out = []
    for region in ALLOWED_REGIONS:
        nodes = sorted(sub_verified_groups.get(region, []), key=lambda x: x['latency'])[:TOP_N]
        other_out.extend([f"{n['ip']}:{n['port']}#{n['tag']}" for n in nodes])
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(other_out))

if __name__ == "__main__":
    main()
