import requests
import base64
import json
import re
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

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
# 域名解析强制地区
DOMAIN_DEFAULT_TAG = "HK"

# API 查询配置
CHECK_API = "https://api.090227.xyz/check"
MAX_WORKERS = 10  # API 并发查询线程数
# ===========================================

def extract_country_from_label(label):
    """从本地备注中提取国家代码"""
    label = label.upper()
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first, second = ord(emoji_chars[0]) - 0x1F1E6, ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    
    cn_map = {
        "香港": "HK", "HK": "HK", "HONG KONG": "HK",
        "日本": "JP", "JP": "JP", "JAPAN": "JP",
        "新加坡": "SG", "SG": "SG", "SINGAPORE": "SG",
        "台湾": "TW", "TW": "TW", "TAIWAN": "TW",
        "美国": "US", "US": "US", "UNITED STATES": "US"
    }
    for name, code in cn_map.items():
        if name in label: return code
    return "UN"

def fetch_country_from_api(ip):
    """通过备选 API 查询 IP 归属地"""
    try:
        # 接口通常需要 ip:port 格式，默认用 443
        params = {"proxyip": f"{ip}:443"}
        resp = requests.get(CHECK_API, params=params, timeout=8).json()
        # 根据该 API 结构提取国家代码
        country = resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN")
        return country.upper()
    except:
        return "UN"

def get_content(url):
    try:
        headers = {'User-Agent': 'v2rayNG/1.8.5'}
        resp = requests.get(url, headers=headers, timeout=15)
        return resp.text if resp.status_code == 200 else None
    except: return None

def process_un_ips(un_ip_list):
    """并发处理未知地区的 IP"""
    results = {}
    if not un_ip_list: return results
    
    print(f"    [i] 正在通过 API 查询 {len(un_ip_list)} 个未知地区的 IP...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(fetch_country_from_api, ip): ip for ip in un_ip_list}
        for future in future_to_ip:
            ip = future_to_ip[future]
            tag = future.result()
            results[ip] = tag
    return results

def main():
    domain_ips = set()
    raw_other_data = [] # 格式: (ip, tag)

    for src in SOURCES:
        print(f"[*] 正在处理源: {src}")
        
        # 1. 域名解析
        if not src.startswith("http"):
            try:
                answers = dns.resolver.resolve(src, 'A')
                for rdata in answers:
                    domain_ips.add(f"{rdata.address}#{DOMAIN_DEFAULT_TAG}")
                    print(f"    [+] 域名解析发现 IP: {rdata.address}")
            except: pass
            continue

        # 2. URL 解析
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
                    addr = match.group(1)
                    tag = extract_country_from_label(line.split("#")[-1] if "#" in line else "UN")
            
            if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                raw_other_data.append((addr, tag))

    # --- 处理未知地区 (API 备选方案) ---
    un_ips = [ip for ip, tag in raw_other_data if tag == "UN"]
    api_results = process_un_ips(un_ips)

    # --- 最终汇总与过滤 ---
    final_other_ips = set()
    for ip, tag in raw_other_data:
        # 如果本地没认出来，看 API 的结果
        final_tag = tag if tag != "UN" else api_results.get(ip, "UN")
        if final_tag in ALLOWED_OTHER:
            final_other_ips.add(f"{ip}#{final_tag}")

    # 保存
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(domain_ips))))
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(final_other_ips))))

    print(f"\n[任务完成]")
    print(f"域名解析(锁定HK): {len(domain_ips)} 个")
    print(f"其他(API辅助+地区过滤): {len(final_other_ips)} 个")

if __name__ == "__main__":
    main()
