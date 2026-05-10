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

# 从环境变量读取（新增 CF_BASE_DOMAIN）
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")  # 如：romarmaulion22.ccwu.cc

# 可选：为特定地区指定不同的域名（优先级高于自动拼接）
# 例如：{"SG": "singapore.otherdomain.com"}
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
    """更新指定域名的 DNS A 记录（支持多 IP 负载均衡）"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not record_name:
        print(f"[!] 配置缺失，跳过 {record_name}")
        return
    
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    try:
        print(f"[*] 正在更新域名: {record_name} (IP数: {len(ips)})")
        
        # 1. 查询现有记录
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}).json()
        if not get_resp.get("success"):
            print(f"[!] 查询失败: {get_resp.get('errors')}")
            return

        # 2. 删除旧记录
        for rec in get_resp.get("result", []):
            del_resp = requests.delete(f"{base_url}/{rec['id']}", headers=headers).json()
            if not del_resp.get("success"):
                print(f"    [!] 删除旧记录失败: {del_resp.get('errors')}")

        # 3. 添加新记录
        success_count = 0
        for ip in ips:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }
            post_resp = requests.post(base_url, headers=headers, json=data).json()
            if post_resp.get("success"):
                success_count += 1
            else:
                print(f"    [!] 添加 IP {ip} 失败: {post_resp.get('errors')}")
        
        print(f"[+] {record_name}: 成功更新 {success_count} 条记录")

    except Exception as e:
        print(f"[!] 更新 {record_name} 时异常: {e}")

def process_node(ip, port, initial_tag):
    is_ok, real_region = check_availability(ip, port)
    tag = real_region if real_region != "UN" else initial_tag
    if is_ok and tag in ALLOWED_REGIONS:
        latency = tcp_ping(ip, port)
        if latency < 2000:
            return {"ip": ip, "port": port, "tag": tag, "latency": latency}
    return None

def get_region_domain(region_code):
    """获取地区对应的域名"""
    # 优先使用自定义域名
    if region_code in CUSTOM_DOMAIN_MAP and CUSTOM_DOMAIN_MAP[region_code]:
        return CUSTOM_DOMAIN_MAP[region_code]
    # 否则自动拼接：sg.romarmaulion22.ccwu.cc
    if CF_BASE_DOMAIN:
        return f"{region_code.lower()}.{CF_BASE_DOMAIN}"
    return None

def main():
    raw_data = set()  # (ip, port, tag)
    domain_ips = set()

    # 1. 解析所有源（保持原有逻辑）
    for src in SOURCES:
        if src.startswith("http"):
            headers = {'User-Agent': 'v2rayNG/1.8.5'}
            try:
                content = requests.get(src, headers=headers, timeout=15).text
                try: decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
                except: decoded = content
                for line in decoded.splitlines():
                    addr, port, tag = "", "443", "UN"
                    if "vmess://" in line:
                        v2 = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                        addr, port, tag = v2.get("add"), v2.get("port", "443"), extract_country_local(v2.get("ps", ""))
                    elif "://" in line and "@" in line:
                        match = re.search(r'@(.*?):(\d+)', line)
                        if match:
                            addr, port = match.group(1), match.group(2)
                            tag = extract_country_local(line.split("#")[-1] if "#" in line else "UN")
                    else:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?', line)
                        if match:
                            addr = match.group(1)
                            port = match.group(2) if match.group(2) else "443"
                            tag = extract_country_local(line.split("#")[-1] if "#" in line else "UN")
                    if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                        raw_data.add((addr, port, tag))
            except: pass
        else:
            try:
                for rdata in dns.resolver.resolve(src, 'A'): domain_ips.add(rdata.address)
            except: pass

    # 2. 处理订阅/列表 IP
    print(f"[*] 正在筛选订阅来源的 {len(raw_data)} 个节点...")
    final_other_groups = defaultdict(list)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, port, tag) for ip, port, tag in raw_data]
        for f in futures:
            res = f.result()
            if res: final_other_groups[res['tag']].append(res)

    # 3. 处理域名解析 IP（默认视为 HK）
    print(f"[*] 正在筛选域名解析的 {len(domain_ips)} 个 IP...")
    domain_group = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, "443", "HK") for ip in domain_ips]
        for f in futures:
            res = f.result()
            if res: domain_group.append(res)

    # 4. 分地区更新 DNS（核心逻辑）
    print("\n[*] 开始分地区更新 DNS...")
    
    # 更新各地区子域名（SG→sg.xxx.com, US→us.xxx.com）
    for region in ALLOWED_REGIONS:
        if region in final_other_groups and final_other_groups[region]:
            # 取该地区延迟最低的 TOP_N 个
            sorted_nodes = sorted(final_other_groups[region], key=lambda x: x['latency'])[:TOP_N]
            target_domain = get_region_domain(region)
            if target_domain:
                update_dns_record(target_domain, [n['ip'] for n in sorted_nodes])
            else:
                print(f"[!] 未配置 {region} 的域名，跳过")
        else:
            print(f"[-] {region}: 无可用节点，跳过")

    # 可选：将域名解析的 IP 更新到 hk.xxx.com 或 domain.xxx.com
    if domain_group:
        # 可以更新到 hk 子域名，或单独的 domain 子域名
        hk_domain = get_region_domain("HK")
        if hk_domain:
            sorted_domain = sorted(domain_group, key=lambda x: x['latency'])[:TOP_N]
            update_dns_record(hk_domain, [n['ip'] for n in sorted_domain])

    # 5. 保存文本文件（保持不变）
    other_output = []
    for region in ALLOWED_REGIONS:
        if region in final_other_groups:
            sorted_nodes = sorted(final_other_groups[region], key=lambda x: x['latency'])[:TOP_N]
            other_output.extend([f"{n['ip']}:{n['port']}#{n['tag']}" for n in sorted_nodes])
    
    with open("other_ips.txt", "w") as f: f.write("\n".join(other_output))
    with open("domain_ips.txt", "w") as f: 
        f.write("\n".join([f"{n['ip']}#HK" for n in sorted(domain_group, key=lambda x: x['latency'])[:TOP_N]]))

if __name__ == "__main__":
    main()
