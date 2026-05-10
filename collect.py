import requests
import base64
import json
import re
import socket
import dns.resolver
import time
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

# 允许的地区
ALLOWED_OTHER = {"HK", "JP", "SG", "TW", "US"}
# 每个国家保留的前 10 名
TOP_N = 10

# API 和 测速配置
CHECK_API = "https://api.090227.xyz/check"
MAX_WORKERS_API = 10    # API 查询并发
MAX_WORKERS_PING = 20   # TCP 测速并发
TCP_TIMEOUT = 2         # TCP 超时时间（秒）
# ===========================================

def extract_country_from_label(label):
    label = label.upper()
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first, second = ord(emoji_chars[0]) - 0x1F1E6, ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    cn_map = {"香港": "HK", "日本": "JP", "新加坡": "SG", "台湾": "TW", "美国": "US"}
    for name, code in cn_map.items():
        if name in label: return code
    return "UN"

def fetch_country_from_api(ip):
    try:
        resp = requests.get(CHECK_API, params={"proxyip": f"{ip}:443"}, timeout=5).json()
        return resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
    except: return "UN"

def tcp_ping(ip, port=443):
    """测试 TCP 延迟"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        sock.connect((ip, port))
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return 99999 # 连接失败设为极大值

def process_api_and_ping(ip_list):
    """并发查询 API 和 测速"""
    results = {} # ip -> (tag, latency)
    
    def task(ip):
        tag = fetch_country_from_api(ip)
        latency = tcp_ping(ip) if tag in ALLOWED_OTHER else 99999
        return ip, tag, latency

    print(f"    [i] 正在处理 {len(ip_list)} 个待识别/待测速 IP...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_PING) as executor:
        futures = [executor.submit(task, ip) for ip in ip_list]
        for f in futures:
            ip, tag, lat = f.result()
            results[ip] = (tag, lat)
    return results

def get_content(url):
    try:
        headers = {'User-Agent': 'v2rayNG/1.8.5'}
        resp = requests.get(url, headers=headers, timeout=15)
        return resp.text if resp.status_code == 200 else None
    except: return None

def main():
    all_raw_ips = set() # 格式: (ip, initial_tag)
    domain_results = [] # 格式: (ip, latency)

    for src in SOURCES:
        print(f"[*] 正在处理源: {src}")
        # 1. 域名解析
        if not src.startswith("http"):
            try:
                ips = [rdata.address for rdata in dns.resolver.resolve(src, 'A')]
                with ThreadPoolExecutor(max_workers=MAX_WORKERS_PING) as executor:
                    pings = list(executor.map(tcp_ping, ips))
                for ip, lat in zip(ips, pings):
                    if lat < 99999: domain_results.append((f"{ip}#HK", lat))
            except: pass
            continue

        # 2. URL 内容获取
        content = get_content(src)
        if not content: continue
        try:
            decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
        except: decoded = content

        for line in decoded.splitlines():
            addr, tag = "", "UN"
            if "vmess://" in line:
                try:
                    v2 = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                    addr, tag = v2.get("add"), extract_country_from_label(v2.get("ps", ""))
                except: continue
            elif "://" in line and "@" in line:
                match = re.search(r'@(.*?)(?::|/|\?|#)', line)
                if match:
                    addr = match.group(1)
                    tag = extract_country_from_label(line.split("#")[-1] if "#" in line else "UN")
            else:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    addr, tag = match.group(1), extract_country_from_label(line.split("#")[-1] if "#" in line else "UN")
            
            if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                all_raw_ips.add((addr, tag))

    # --- 统一处理测速和 API 查询 ---
    print(f"[*] 开始进行全球 API 归属地校对与 TCP 测速...")
    ip_to_test = [ip for ip, tag in all_raw_ips]
    # 如果本地能识别出国家且不是 UN，我们也测速，但如果识别不出，API 辅助
    processed_data = process_api_and_ping(ip_to_test)

    # --- 分组与排序 ---
    country_groups = defaultdict(list)
    for ip, initial_tag in all_raw_ips:
        api_tag, latency = processed_data.get(ip, ("UN", 99999))
        # 优先使用 API 识别出的国家，因为更准
        final_tag = api_tag if api_tag != "UN" else initial_tag
        
        if final_tag in ALLOWED_OTHER and latency < 99999:
            country_groups[final_tag].append((f"{ip}#{final_tag}", latency))

    # --- 筛选 Top 10 ---
    final_other_ips = []
    for country in ALLOWED_OTHER:
        # 按延迟排序
        sorted_list = sorted(country_groups[country], key=lambda x: x[1])
        top_10 = sorted_list[:TOP_N]
        final_other_ips.extend([item[0] for item in top_10])
        print(f"    [+] {country}: 筛选出 {len(top_10)} 个优质节点")

    # 域名解析结果也取前 10
    domain_top_10 = [item[0] for item in sorted(domain_results, key=lambda x: x[1])[:TOP_N]]

    # 保存文件
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(domain_top_10))
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_other_ips))

    print(f"\n[任务完成] 域名 Top10 已保存, 其他各国家 Top10 已保存。")

if __name__ == "__main__":
    main()
