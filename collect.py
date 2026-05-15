import requests
import base64
import json
import os
import random
import time
from collections import defaultdict
from urllib.parse import urlparse, unquote

# ================= 配置 =================

# 主域名
BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

# Cloudflare
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")

# ProxyIP 域名
PROXYIP_DOMAINS = [
    "tw.william.us.ci",
    "kr.william.us.ci",
    "sjc.o00o.ooo",
    "ProxyIP.JP.CMLiussss.net",
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.SG.CMLiussss.net",
]

# 订阅源
SUB_SOURCES = [
    "https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
    "https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
    "https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
    "https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
]

# 每地区随机保留数量
TOP_N = 5

# 允许地区
ALLOWED_REGIONS = {"HK", "JP", "SG", "KR", "TW", "US"}

# IP段过滤 (留空 = 不过滤)
ALLOWED_IP_PREFIX = {
    "HK": ["219."],
    "JP": [],
    "SG": [],
    "KR": [],
    "TW": [],
    "US": [],
}

# ProxyIP API
CHECK_API = "https://check.proxyip.cmliussss.net/api/check"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)

def ip_match_region(ip, region):
    prefixes = ALLOWED_IP_PREFIX.get(region)
    if not prefixes:
        return True
    return any(ip.startswith(p) for p in prefixes)

def safe_b64decode(data):
    """鲁棒性极强的 Base64 解码器，兼容 URL-Safe 格式"""
    try:
        data = data.strip()
        if not data:
            return None
            
        # 兼容 URL-safe 编码
        data = data.replace('-', '+').replace('_', '/')
        
        # 补齐等号
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding

        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        # log(f"[Debug] Base64 解码错误: {e}")
        return None

def parse_node_link(line):
    """增强版节点解析器，准确提取所有协议的 IP:Port"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # 1. 解析 vmess://
    if line.startswith("vmess://"):
        try:
            raw = line[8:]
            decoded = safe_b64decode(raw)
            if not decoded:
                return None
            obj = json.loads(decoded)
            add = obj.get("add") or obj.get("sni") or obj.get("host")
            port = str(obj.get("port", "443"))
            if add:
                return str(add).strip(), port
        except Exception:
            return None

    # 2. 解析通用协议 (vless://, trojan://, ss:// 等)
    if "://" in line:
        try:
            # 移除 URL 中的 remark (#xxx) 避免干扰解析
            clean_url = line.split("#")[0]
            
            # 使用 Python 标准库解析 URL
            parsed = urlparse(clean_url)
            
            # urlparse 自动处理 IPv6 (例如 [2400:cb00::1]) 和 @ 前面的认证信息
            host = parsed.hostname
            port = parsed.port
            
            if not port:
                port = 443
                
            if host:
                # 移除 IPv6 可能自带的括号
                host = unquote(str(host)).strip("[]")
                return host, str(port)
                
        except Exception as e:
            # log(f"[Debug] URL 解析失败 ({line[:20]}...): {e}")
            return None

    return None

# ================= ProxyIP 核心 =================

def fetch_proxyip_backend(domain):
    """
    重复请求 API 获取多个真实后端节点，增加错误排查提示
    """
    results = set()
    fail_count = 0

    for i in range(20):
        try:
            resp = requests.get(CHECK_API, params={"target": domain}, headers=HEADERS, timeout=10)
            
            if resp.status_code != 200:
                if fail_count == 0:
                    log(f"   [!] API HTTP {resp.status_code}: {resp.text[:50]}")
                fail_count += 1
                time.sleep(1)
                continue

            try:
                data = resp.json()
            except json.JSONDecodeError:
                if fail_count == 0:
                    log(f"   [!] API 未返回 JSON，可能被拦截。返回值摘要: {resp.text[:50]}")
                fail_count += 1
                time.sleep(1)
                continue

            # 兼容不同返回格式
            targets = []
            if isinstance(data, dict):
                targets = data.get("results") or data.get("data") or data.get("targets") or []
            elif isinstance(data, list):
                targets = data

            if not targets and fail_count == 0:
                log(f"   [-] API 返回内容正常，但列表为空。")

            for item in targets:
                if not isinstance(item, dict):
                    continue

                ip = item.get("ip")
                port = str(item.get("port", "443"))
                region = (item.get("country") or item.get("region") or "").upper()

                if not ip or region not in ALLOWED_REGIONS:
                    continue
                if not ip_match_region(ip, region):
                    continue

                results.add((ip, port, region))

        except requests.RequestException as e:
            if fail_count == 0:
                log(f"   [!] 网络请求异常: {e}")
            fail_count += 1

        time.sleep(0.3)

    return list(results)

# ================= Cloudflare =================

def update_cloudflare_dns(region, ips):
    if not ips or not BASE_DOMAIN or not CF_API_TOKEN or not CF_ZONE_ID:
        log(f"[!] 跳过 CF 更新：缺少必要的环境变量或 IP 列表为空 ({region})")
        return

    record_name = f"{region.lower()}.{BASE_DOMAIN}"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    log(f"\n[CF] 更新 {record_name}")

    try:
        # 删除旧记录
        old_resp = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=15)
        old = old_resp.json()

        if old.get("success"):
            for rec in old.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=15)

        # 添加新记录
        for ip in ips:
            # 自动识别 IPv4(A) 和 IPv6(AAAA)
            record_type = "AAAA" if ":" in ip else "A"
            payload = {
                "type": record_type,
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }
            res = requests.post(base_url, headers=headers, json=payload, timeout=15)
            if res.status_code == 200:
                log(f"   -> [{record_type}] {ip}")
            else:
                log(f"   [!] 添加失败 {ip}: {res.text}")

    except Exception as e:
        log(f"[!] CF 更新失败: {e}")

# ================= 主流程 =================

def main():
    log("=" * 60)
    log("🚀 ProxyIP 自动更新开始")
    log("=" * 60)

    region_result = defaultdict(set)

    # ================= 1. 获取 ProxyIP =================
    for domain in PROXYIP_DOMAINS:
        log(f"\n🌐 请求节点检测 API: {domain}")
        results = fetch_proxyip_backend(domain)

        if not results:
            log("   -> 最终未能提取到符合条件的节点")
            continue

        for ip, port, region in results:
            log(f"   -> {ip}:{port} [{region}]")
            region_result[region].add((ip, port))

    # ================= 2. 更新 DNS =================
    domain_output_lines = []
    
    for region in sorted(region_result.keys()):
        items = list(region_result[region])
        random.shuffle(items)
        
