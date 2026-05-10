import requests
import base64
import json
import re
import socket
import dns.resolver

# ================= 配置区域 =================
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "ProxyIP.HK.CMLiussss.net",
    "https://sub.xinyitang.dpdns.org/sub?host=gmail-auto.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=%2F" 
]
# ===========================================

def extract_country(label):
    """提取国家代码"""
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2:
        first, second = ord(emoji_chars[0]) - 0x1F1E6, ord(emoji_chars[1]) - 0x1F1E6
        return chr(first + ord('A')) + chr(second + ord('A'))
    cn_map = {"香港": "HK", "美国": "US", "日本": "JP", "台湾": "TW", "新加坡": "SG", "韩国": "KR"}
    for name, code in cn_map.items():
        if name in label: return code
    return "UN"

def parse_any_text_for_ips(text):
    """终极提取：从任何乱糟糟的文本里提取 IP#国家"""
    results = set()
    # 匹配所有的 IPv4:端口#标签 或者 纯IPv4
    lines = text.splitlines()
    for line in lines:
        # 提取 IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip = ip_match.group(1)
            # 提取备注
            label = "UN"
            if "#" in line:
                label = extract_country(line.split("#")[-1])
            elif "ps=" in line: # 处理一些直连参数
                label = extract_country(line.split("ps=")[-1])
            results.add(f"{ip}#{label}")
    return results

def get_content(url):
    """获取网页内容，带上 User-Agent"""
    try:
        headers = {'User-Agent': 'v2rayNG/1.8.5'}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        print(f"  [!] 请求失败 {url}: {e}")
    return None

def main():
    domain_ips = set()
    other_ips = set()

    for src in SOURCES:
        print(f"[*] 正在处理源: {src}")
        
        # 1. 域名解析
        if not src.startswith("http"):
            print(f"    检测到域名，正在解析 A 记录...")
            try:
                answers = dns.resolver.resolve(src, 'A')
                for rdata in answers:
                    domain_ips.add(f"{rdata.address}#HK")
                    print(f"    [+] 域名解析发现 IP: {rdata.address}")
            except Exception as e:
                print(f"    [!] 域名解析出错: {e}")
            continue

        # 2. 处理 URL（订阅或文本）
        content = get_content(src)
        if not content:
            continue

        # 尝试 Base64 解码
        try:
            # 补齐长度并解码
            decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
            print(f"    [+] 成功识别并解码 Base64 内容")
        except:
            decoded = content
            print(f"    [i] 内容非 Base64，作为纯文本处理")

        # 提取 IP
        # 如果包含 vmess/vless 特征，先提取里面的 add 字段
        if "vmess://" in decoded or "vless://" in decoded:
            print(f"    正在从节点协议中提取地址...")
            for line in decoded.splitlines():
                if "vmess://" in line:
                    try:
                        v2_data = json.loads(base64.b64decode(line[8:]).decode('utf-8'))
                        addr = v2_data.get("add")
                        if addr: other_ips.add(f"{addr}#{extract_country(v2_data.get('ps',''))}")
                    except: pass
                elif "://" in line and "@" in line:
                    # 匹配 vless://uuid@address:port...#label
                    match = re.search(r'@(.*?)(?::|/|\?|#)', line)
                    if match:
                        addr = match.group(1)
                        label = line.split("#")[-1] if "#" in line else "UN"
                        other_ips.add(f"{addr}#{extract_country(label)}")
        else:
            # 否则直接强力匹配 IP
            found = parse_any_text_for_ips(decoded)
            print(f"    [+] 强力匹配发现 {len(found)} 个 IP")
            other_ips.update(found)

    # 结果写入
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(domain_ips))))
    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(other_ips))))

    print(f"\n[任务完成] 域名IP: {len(domain_ips)} 个, 其他IP: {len(other_ips)} 个")

if __name__ == "__main__":
    main()
