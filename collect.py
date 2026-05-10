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
    "sjc.o00o.ooo",
    "kr.william.us.ci",
    "proxy.xinyitang.dpdns.org"
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://sub.cmliussss.net/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://owo.o00o.ooo/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" ,
    "https://cm.soso.edu.kg/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" 
]

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

# 从 GitHub Secrets 获取环境变量
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
CF_RECORD_NAME = os.getenv("CF_RECORD_NAME")
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

def check_availability_and_get_region(ip, port):
    """调用 API 验证可用性并获取真实地区"""
    try:
        resp = requests.get(CHECK_API, params={"proxyip": f"{ip}:{port}"}, timeout=10).json()
        if resp.get("success") is True:
            # 提取 API 识别的国家
            region = resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
            return True, region
    except: pass
    return False, "UN"

def tcp_ping(ip, port):
    """测试 TCP 延迟"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, int(port)))
        sock.close()
        return int((time.time() - start) * 1000)
    except: return 99999

def update_cloudflare_dns(ips):
    """更新 Cloudflare DNS 记录 (增强调试版)"""
    if not CF_API_TOKEN or not CF_ZONE_ID or not CF_RECORD_NAME:
        print("[!] 错误: 缺失环境变量 CF_API_TOKEN, CF_ZONE_ID 或 CF_RECORD_NAME")
        return

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    # 基础 URL
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    try:
        # 1. 获取现有记录
        # 注意：name 参数必须是完整域名，如 cf.example.com
        print(f"[*] 正在查询域名记录: {CF_RECORD_NAME}")
        params = {"name": CF_RECORD_NAME}
        get_resp = requests.get(base_url, headers=headers, params=params).json()
        
        if not get_resp.get("success"):
            print(f"[!] 查询失败，CF 报错: {get_resp.get('errors')}")
            return

        # 2. 删除现有记录
        existing_records = get_resp.get("result", [])
        print(f"[*] 发现 {len(existing_records)} 条现有记录，准备删除...")
        for rec in existing_records:
            del_resp = requests.delete(f"{base_url}/{rec['id']}", headers=headers).json()
            if not del_resp.get("success"):
                print(f"    [!] 删除记录 {rec['id']} 失败: {del_resp.get('errors')}")

        # 3. 批量添加新记录
        print(f"[*] 正在添加 {len(ips)} 条新 A 记录...")
        success_count = 0
        for ip in ips:
            data = {
                "type": "A",
                "name": CF_RECORD_NAME,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }
            post_resp = requests.post(base_url, headers=headers, json=data).json()
            if post_resp.get("success"):
                success_count += 1
            else:
                # 打印具体的错误原因，比如 "Invalid domain name" 或 "Record already exists"
                print(f"    [!] 添加 IP {ip} 失败: {post_resp.get('errors')}")
        
        if success_count > 0:
            print(f"[+] 成功更新 {success_count} 条记录到 DNS: {CF_RECORD_NAME}")
        else:
            print("[!] 未能成功更新任何记录，请检查上方报错信息。")

    except Exception as e:
        print(f"[!] 脚本执行异常: {e}")

def process_node(ip, port, initial_tag):
    """单个节点的处理流程"""
    is_ok, real_region = check_availability_and_get_region(ip, port)
    tag = real_region if real_region != "UN" else initial_tag
    
    if is_ok and tag in ALLOWED_REGIONS:
        latency = tcp_ping(ip, port)
        if latency < 2000:
            return {"ip": ip, "port": port, "tag": tag, "latency": latency}
    return None

def main():
    raw_data = set() # (ip, port, initial_tag)
    domain_ips = set()

    # 1. 解析所有源
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
                    elif "@" in line:
                        # 匹配 vless/trojan 格式 @address:port
                        match = re.search(r'@(.*?):(\d+)', line)
                        if match: 
                            addr, port = match.group(1), match.group(2)
                            tag = extract_country_local(line.split("#")[-1] if "#" in line else "UN")
                    else:
                        # 匹配纯文本 1.1.1.1:443 或 1.1.1.1
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

    # 2. 处理订阅/列表 IP (带端口)
    print(f"[*] 正在对 {len(raw_data)} 个节点进行可用性与延迟筛选...")
    final_other_groups = defaultdict(list)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, port, tag) for ip, port, tag in raw_data]
        for f in futures:
            res = f.result()
            if res: final_other_groups[res['tag']].append(res)

    other_output = []
    for region in ALLOWED_REGIONS:
        sorted_nodes = sorted(final_other_groups[region], key=lambda x: x['latency'])[:TOP_N]
        # 保存格式 IP:端口#地区
        other_output.extend([f"{n['ip']}:{n['port']}#{n['tag']}" for n in sorted_nodes])
        print(f"    - {region} 筛选出 {len(sorted_nodes)} 个节点")

    # 3. 特别处理域名解析 IP (默认 443 测速)
    print(f"[*] 正在筛选域名解析出的 {len(domain_ips)} 个 IP...")
    domain_verified = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_node, ip, "443", "HK") for ip in domain_ips]
        for f in futures:
            res = f.result()
            if res: domain_verified.append(res)
    
    domain_sorted = sorted(domain_verified, key=lambda x: x['latency'])[:TOP_N]
    domain_output = [f"{n['ip']}#HK" for n in domain_sorted]
    
    # 4. 执行更新与保存
    with open("domain_ips.txt", "w") as f: f.write("\n".join(domain_output))
    with open("other_ips.txt", "w") as f: f.write("\n".join(other_output))
    
    if domain_sorted:
        # DNS A记录不含端口，只取 IP
        update_cloudflare_dns([n['ip'] for n in domain_sorted])

if __name__ == "__main__":
    main()
