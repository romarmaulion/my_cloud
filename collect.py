import requests
import base64
import json
import re
import socket
import dns.resolver

# ================= 配置区域 =================
# 在这里填入你的所有来源
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",               # 远程文本列表
    "ProxyIP.HK.CMLiussss.net",                    # 域名
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/" # 替换成你真实的订阅链接
]
# ===========================================

def extract_country(label):
    """从标签中提取国家代码"""
    # 匹配 Emoji 国旗
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first, second = ord(emoji_chars[0]) - 0x1F1E6, ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    # 常见中文名匹配
    cn_map = {"香港": "HK", "美国": "US", "日本": "JP", "台湾": "TW", "新加坡": "SG", "韩国": "KR"}
    for name, code in cn_map.items():
        if name in label: return code
    return "UN"

def parse_sub(url):
    """解析订阅链接提取 IP"""
    ips = set()
    try:
        headers = {'User-Agent': 'v2rayNG/1.8.5'}
        content = requests.get(url, headers=headers, timeout=15).text
        try:
            decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
        except:
            decoded = content
        
        for line in decoded.splitlines():
            addr, label = "", "UN"
            if "vmess://" in line:
                data = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                addr, label = data.get("add"), data.get("ps", "")
            elif "@" in line and "://" in line:
                match = re.search(r'@(.*?):(\d+).*#(.*)', line)
                if match: addr, label = match.group(1), match.group(3)
            
            if addr and re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                ips.add(f"{addr}#{extract_country(label)}")
    except: pass
    return ips

def parse_domain(domain):
    """解析域名提取 IP"""
    ips = set()
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.add(f"{rdata.address}#HK") # 域名解析通常默认为HK，或改为UN
    except: pass
    return ips

def parse_txt(url):
    """解析远程文本提取 IP"""
    ips = set()
    try:
        content = requests.get(url, timeout=15).text
        for line in content.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                label = line.split('#')[-1] if '#' in line else "UN"
                ips.append(f"{ip}#{extract_country(label)}")
    except: pass
    return ips

def main():
    domain_ips = set()
    other_ips = set()

    for src in SOURCES:
        if "sub?" in src or "token=" in src or "vmess" in src:
            other_ips.update(parse_sub(src))
        elif src.startswith("http"):
            other_ips.update(parse_txt(src))
        else:
            domain_ips.update(parse_domain(src))

    # 写入文件
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(domain_ips))))
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(other_ips))))

if __name__ == "__main__":
    main()
