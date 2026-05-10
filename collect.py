import requests
import base64
import json
import re
import socket
import os
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区域 =================
# 支持：订阅链接(vmess/vless)、纯域名(A记录)、远程txt链接
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "ProxyIP.HK.CMLiussss.net",
    "https://sub.xinyitang.dpdns.org/sub?host=你的参数" # 填入你的订阅链接
]

# 国家代码映射 (截取自你提供的代码)
CN_TO_CODE = {"香港": "HK", "美国": "US", "日本": "JP", "台湾": "TW", "新加坡": "SG", "韩国": "KR", "英国": "GB", "德国": "DE", "中国": "CN"}

# ================= 核心逻辑 =================

def extract_country_code(label):
    """从标签或 Emoji 中提取国家代码"""
    # 匹配 Emoji 国旗
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first = ord(emoji_chars[0]) - 0x1F1E6
        second = ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    
    # 匹配中文
    for name, code in CN_TO_CODE.items():
        if name in label: return code
    
    # 匹配标准两位代码 (如 #US)
    match = re.search(r'([A-Z]{2})$', label.strip())
    return match.group(1) if match else "UN"

def get_geo_ip(ip):
    """对于没有标签的IP，通过API获取地理位置"""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5).json()
        return resp.get("countryCode", "UN")
    except: return "UN"

def parse_subscription(url):
    """解析订阅链接"""
    ips = []
    try:
        headers = {'User-Agent': 'v2rayNG/1.8.5'}
        resp = requests.get(url, headers=headers, timeout=15).text
        try:
            # 尝试 Base64 解码
            decoded = base64.b64decode(resp + '=' * (-len(resp) % 4)).decode('utf-8')
        except:
            decoded = resp
        
        for line in decoded.splitlines():
            addr, label = "", "Unknown"
            if "vmess://" in line:
                data = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                addr, label = data.get("add"), data.get("ps", "Unknown")
            elif "@" in line and "://" in line:
                match = re.search(r'@(.*?):(\d+).*#(.*)', line)
                if match: addr, label = match.group(1), match.group(3)
            
            if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                ips.append(f"{addr}#{extract_country_code(label)}")
    except: pass
    return ips

def parse_domain(domain):
    """解析域名 A 记录"""
    ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        answers = resolver.resolve(domain, 'A')
        code = extract_country_code(domain) # 尝试从域名本身拿国家
        if code == "UN": code = "HK" # 默认域名为HK节点，或可改为API查询
        for rdata in answers:
            ips.append(f"{rdata.address}#{code}")
    except: pass
    return ips

def parse_remote_txt(url):
    """解析远程文本 IP 列表"""
    ips = []
    try:
        resp = requests.get(url, timeout=15).text
        for line in resp.splitlines():
            # 匹配 1.1.1.1:443#US 或 1.1.1.1
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                label = line.split('#')[-1] if '#' in line else "UN"
                ips.append(f"{ip}#{extract_country_code(label)}")
    except: pass
    return ips

def main():
    domain_results = []
    other_results = []

    for src in SOURCES:
        print(f"正在处理: {src}")
        if "sub?" in src or "token=" in src:
            other_results.extend(parse_subscription(src))
        elif src.startswith("http"):
            other_results.extend(parse_remote_txt(src))
        else:
            domain_results.extend(parse_domain(src))

    # 去重保存
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(set(domain_results)))))

    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(set(other_results)))))

    print(f"完成！域名IP: {len(domain_results)}, 其他IP: {len(other_results)}")

if __name__ == "__main__":
    main()
