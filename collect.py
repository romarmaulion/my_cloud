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
TOP_N = 5
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
    """更新指定域名的 DNS A 记录 (去重增强版)"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not record_name:
        print(f"[!] 配置缺失，跳过 {record_name}")
        return
    
    # --- 核心修复 1: 强制去重 ---
    ips = sorted(list(set(ips))) 
    
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    try:
        print(f"[*] 正在更新域名: {record_name} (唯一IP数: {len(ips)})")
        
        # 1. 查询并删除旧记录
        get_resp = requests.get(base_url, headers=headers, params={"name": record_name}).json()
        if get_resp.get("success"):
            existing_records = get_resp.get("result", [])
            for rec in existing_records:
                requests.delete(f"{base_url}/{rec['id']}", headers=headers)
        
        # 2. 批量添加新记录
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
                # --- 核心修复 2: 忽略“记录已存在”的错误 ---
                errors = post_resp.get('errors', [])
                if any(e.get('code') == 81058 for e in errors):
                    print(f"    [i] IP {ip} 已存在，跳过")
                    success_count += 1 # 既然已经存在，也算作成功
                else:
                    print(f"    [!] 添加 IP {ip} 失败: {errors}")
        
        print(f"[+] {record_name}: 成功保持 {success_count} 条记录有效")

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
    raw_data = set()      # 用于存储来自订阅链接的 (ip, port, tag)
    domain_raw_ips = set() # 用于存储来自域名解析的 IP

    # 1. 解析所有源
    for src in SOURCES:
        if src.startswith("http"):
            # 处理订阅/远程链接逻辑 (保持不变)
            # ... 提取结果放入 raw_data ...
        else:
            # 处理域名解析逻辑 (ProxyIP.HK... 等)
            try:
                for rdata in dns.resolver.resolve(src, 'A'):
                    domain_raw_ips.add(rdata.address)
            except: pass

    # 2. 【管道 A】处理“域名解析”出的 IP -> 目标：DNS 更新 + 文件保存
    print(f"[*] 正在筛选域名解析出的 {len(domain_raw_ips)} 个 IP...")
    domain_verified_groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=10) as executor:
        # 我们对域名解析出的 IP 依然调用 API 检查真实地区和延迟
        futures = [executor.submit(process_node, ip, "443", "HK") for ip in domain_raw_ips]
        for f in futures:
            res = f.result()
            if res:
                domain_verified_groups[res['tag']].append(res)

    # 3. 【管道 B】处理“订阅链接”出的 IP -> 目标：仅文件保存
    print(f"[*] 正在筛选订阅来源的 {len(raw_data)} 个节点...")
    sub_verified_groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, port, tag) for ip, port, tag in raw_data]
        for f in futures:
            res = f.result()
            if res:
                sub_verified_groups[res['tag']].append(res)

    # --- 核心操作 1：更新 DNS (仅使用域名解析的结果) ---
    print("\n[*] 正在同步域名解析结果到 Cloudflare DNS...")
    for region in ALLOWED_REGIONS:
        # 只从域名解析的组里拿数据
        nodes = domain_verified_groups.get(region, [])
        if nodes:
            sorted_nodes = sorted(nodes, key=lambda x: x['latency'])[:TOP_N]
            target_domain = get_region_domain(region)
            if target_domain:
                update_dns_record(target_domain, [n['ip'] for n in sorted_nodes])
        else:
            print(f"[-] {region} (域名源): 无可用节点，跳过 DNS 更新")

    # --- 核心操作 2：保存文件 ---
    # 保存 domain_ips.txt (仅包含域名解析结果)
    domain_output = []
    for region, nodes in domain_verified_groups.items():
        for n in nodes:
            domain_output.append(f"{n['ip']}#{n['tag']}")
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_output)))

    # 保存 other_ips.txt (仅包含订阅解析结果)
    other_output = []
    for region in ALLOWED_REGIONS:
        nodes = sub_verified_groups.get(region, [])
        # 每个地区取前 Top_N 个保存到文件
        sorted_nodes = sorted(nodes, key=lambda x: x['latency'])[:TOP_N]
        for n in sorted_nodes:
            other_output.append(f"{n['ip']}:{n['port']}#{n['tag']}")
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(other_output))

    print(f"\n[任务完成] DNS 已更新(仅限域名源)，文件已分类保存。")

if __name__ == "__main__":
    main()
