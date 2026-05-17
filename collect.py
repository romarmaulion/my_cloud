import requests
import base64
import json
import re
import socket
import dns.resolver
import os
import ipaddress
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 配置区域 =================

SOURCES = [
    ("ProxyIP.HK.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.JP.CMLiussss.net", "DOMAIN"),
    ("ProxyIP.SG.CMLiussss.net", "DOMAIN"),
    ("sjc.o00o.ooo", "DOMAIN"),
    ("tw.william.us.ci", "DOMAIN"),
    ("kr.william.us.ci", "DOMAIN"),
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

ONLINE_IP_FILES = [
    "https://zip.cm.edu.kg/all.txt",
]

REGION_FILTERS = {
    "HK": ["219.0.0.0/8"],
    "TW": [],
    "KR": [],
    "US": [],
    "JP": [],
    "SG": [],
}

ALLOWED_REGIONS = set(REGION_FILTERS.keys())
DOMAIN_TOP_N = 3
FINAL_TOP_N = 5
MAX_WORKERS = 50
HOSTING_CHECK_WORKERS = 20
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
BASE_DOMAIN = os.getenv("BASE_DOMAIN")


# ================= 机房IP多源检测器 =================

class HostingChecker:
    def __init__(self):
        self.sources = [
            self._check_ip_api,
            self._check_ipapi_co,
            self._check_ipinfo,
            self._check_ipwhois,
            self._check_ipdata,
        ]

    def _check_ip_api(self, ip):
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,hosting,proxy,isp",
                timeout=5
            )
            if resp.status_code == 429:
                return None
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "is_hosting": data.get("hosting", False),
                    "isp": data.get("isp", ""),
                    "source": "ip-api.com"
                }
        except Exception:
            pass
        return None

    def _check_ipapi_co(self, ip):
        try:
            resp = requests.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 429:
                return None
            data = resp.json()
            if data.get("error"):
                return None
            org = data.get("org", "").lower()
            kw = [
                "cloudflare", "amazon", "google", "microsoft",
                "digitalocean", "vultr", "linode", "ovh",
                "hetzner", "bandwagon", "choopa", "contabo",
                "hostinger", "kamatera", "upcloud", "oracle",
                "alibaba", "tencent", "data center", "hosting",
                "server", "cloud", "vps", "dedicated"
            ]
            return {
                "is_hosting": any(k in org for k in kw),
                "isp": data.get("org", ""),
                "source": "ipapi.co"
            }
        except Exception:
            pass
        return None

    def _check_ipinfo(self, ip):
        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 429:
                return None
            data = resp.json()
            org = data.get("org", "").lower()
            hostname = data.get("hostname", "").lower()
            kw = [
                "cloudflare", "amazon", "google", "microsoft",
                "digitalocean", "vultr", "linode", "ovh",
                "hetzner", "bandwagon", "choopa", "contabo",
                "hosting", "server", "cloud", "vps", "data center"
            ]
            return {
                "is_hosting": (
                    any(k in org for k in kw) or
                    any(k in hostname for k in ["cloud", "server", "vps", "host", "node"])
                ),
                "isp": data.get("org", ""),
                "source": "ipinfo.io"
            }
        except Exception:
            pass
        return None

    def _check_ipwhois(self, ip):
        try:
            resp = requests.get(f"https://ipwhois.app/json/{ip}", timeout=5)
            if resp.status_code == 429:
                return None
            data = resp.json()
            if data.get("success"):
                isp = data.get("isp", "").lower()
                ct = data.get("connection_type", "").lower()
                kw = [
                    "cloudflare", "amazon", "google", "microsoft",
                    "digitalocean", "vultr", "linode", "ovh",
                    "hetzner", "bandwagon", "hosting", "cloud",
                    "server", "data center", "vps"
                ]
                return {
                    "is_hosting": any(k in isp for k in kw) or ct in ["dcn", "hosting"],
                    "isp": data.get("isp", ""),
                    "source": "ipwhois.app"
                }
        except Exception:
            pass
        return None

    def _check_ipdata(self, ip):
        try:
            resp = requests.get(f"https://api.ipdata.co/{ip}?api-key=test", timeout=5)
            if resp.status_code == 429:
                return None
            data = resp.json()
            threat = data.get("threat", {})
            return {
                "is_hosting": (
                    threat.get("is_datacenter", False) or
                    threat.get("is_proxy", False) or
                    threat.get("is_anonymous", False)
                ),
                "isp": data.get("asn", {}).get("name", ""),
                "source": "ipdata.co"
            }
        except Exception:
            pass
        return None

    def check(self, ip):
        sources = self.sources.copy()
        random.shuffle(sources)
        for fn in sources:
            result = fn(ip)
            if result is not None:
                return result
        return None


# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)


def is_ip_in_allowed_subnets(ip, region):
    subnets = REGION_FILTERS.get(region, [])
    if not subnets:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in subnets:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True
    except Exception:
        pass
    return False


def resolve_domain(domain):
    ips = set()
    dns_servers = [
        ["1.1.1.1", "1.0.0.1"],
        ["8.8.8.8", "8.8.4.4"],
        ["9.9.9.9"],
    ]
    for servers in dns_servers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = servers
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.add(rdata.address)
            if ips:
                return ips
        except Exception:
            continue
    try:
        ips.add(socket.gethostbyname(domain))
    except Exception:
        pass
    return ips


def safe_b64decode(data):
    if not data:
        return None
    data = re.sub(r'[^a-zA-Z0-9+/=]', '', data.strip())
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return None


def check_region(ip, port):
    try:
        resp = requests.get(
            CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=10
        ).json()
        if resp.get("success"):
            return resp.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "UN").upper()
    except Exception:
        pass
    return "UN"


def update_cf_dns(region, ips):
    if not all([CF_API_TOKEN, CF_ZONE_ID, BASE_DOMAIN]):
        return
    record_name = f"{region.lower()}.{BASE_DOMAIN}"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    try:
        res = requests.get(base_url, headers=headers, params={"name": record_name}, timeout=10).json()
        if res.get("success"):
            for rec in res.get("result", []):
                requests.delete(f"{base_url}/{rec['id']}", headers=headers, timeout=10)
        for ip in ips:
            requests.post(base_url, headers=headers, json={
                "type": "A", "name": record_name, "content": ip, "ttl": 60, "proxied": False
            }, timeout=10)
        log(f"      [CF] {record_name} 已更新 ({len(ips)} 条)")
    except Exception as e:
        log(f"      [!] CF更新失败: {e}")


# ================= 网络文件解析（直接读取地区标记） =================

def fetch_online_ips(url):
    """
    从网络文件下载IP列表，直接解析地区标记
    支持格式:
      103.125.216.82:8443#JP
      1.2.3.4#HK
      5.6.7.8:443#SG
    返回: {region: [(ip, port), ...]}
    """
    region_ips = {r: [] for r in ALLOWED_REGIONS}
    total_count = 0
    matched_count = 0

    try:
        log(f"   📥 下载: {url}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total_count += 1

            # 解析格式: IP:端口#地区 或 IP#地区
            if "#" not in line:
                continue

            ip_port_part, region = line.rsplit("#", 1)
            region = region.strip().upper()

            if region not in ALLOWED_REGIONS:
                continue

            # 分离 IP 和端口
            ip_port_part = ip_port_part.strip()
            if ":" in ip_port_part:
                ip_part, port_part = ip_port_part.rsplit(":", 1)
                port_part = re.sub(r'[^0-9]', '', port_part)
                if not port_part:
                    port_part = "443"
            else:
                ip_part = ip_port_part
                port_part = "443"

            # 验证 IP
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_part):
                try:
                    ipaddress.ip_address(ip_part)
                    region_ips[region].append((ip_part, port_part))
                    matched_count += 1
                except ValueError:
                    pass

        log(f"   ✅ 总行数: {total_count}, 匹配目标地区: {matched_count}")
        for r in sorted(ALLOWED_REGIONS):
            if region_ips[r]:
                log(f"      {r}: {len(region_ips[r])} 个IP")

    except Exception as e:
        log(f"   ❌ 下载失败: {e}")

    return region_ips


# ================= 订阅内容解析 =================

def parse_sub_content(content):
    """
    解析订阅内容，提取所有 IP:端口
    支持 vmess/vless/trojan/ss 协议
    """
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # vmess:// base64 JSON
        if line.startswith("vmess://"):
            try:
                raw = line[8:].split("#")[0]
                decoded = safe_b64decode(raw)
                if decoded:
                    j = json.loads(decoded)
                    host = j.get("add", "")
                    port = str(j.get("port", "443"))
                    if host and port:
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                            results.append((host, port))
                        else:
                            for ip in resolve_domain(host):
                                results.append((ip, port))
            except Exception:
                pass
            continue

        # vless/trojan/ss 标准 URI
        if "://" in line:
            try:
                body = line.split("#")[0]
                after_proto = body.split("://", 1)[1]
                if "@" in after_proto:
                    after_proto = after_proto.rsplit("@", 1)[1]
                host_port = after_proto.split("/")[0].split("?")[0]
                if host_port.startswith("["):
                    continue
                if ":" in host_port:
                    h, p = host_port.rsplit(":", 1)
                else:
                    h, p = host_port, "443"
                p = re.sub(r'[^0-9]', '', p)
                if not p:
                    p = "443"
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                    results.append((h, p))
                else:
                    for ip in resolve_domain(h):
                        results.append((ip, p))
            except Exception:
                pass

    return results


# ================= 机房IP批量检测 =================

def batch_check_hosting(ip_port_region_list):
    """
    两轮检测:
    第一轮: ip-api 批量接口 (100个/次)
    第二轮: 多源轮询兜底
    """
    all_ips = list(set([ip for ip, port, region in ip_port_region_list]))
    total = len(all_ips)
    log(f"\n🔍 开始机房IP检测 | 共 {total} 个IP（去重后）")

    batch_results = {}

    # 第一轮: ip-api 批量接口
    log(f"   📦 第一轮: ip-api 批量接口...")
    for i in range(0, len(all_ips), 100):
        batch = all_ips[i:i + 100]
        payload = [{"query": ip, "fields": "query,status,hosting,isp"} for ip in batch]
        try:
            resp = requests.post("http://ip-api.com/batch", json=payload, timeout=15)
            if resp.status_code == 200:
                for item in resp.json():
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        batch_results[ip] = {
                            "is_hosting": item.get("hosting", False),
                            "isp": item.get("isp", ""),
                            "source": "ip-api-batch"
                        }
            time.sleep(1.5)
        except Exception as e:
            log(f"      批量查询异常: {e}")
        log(f"      进度: [{min(i + 100, len(all_ips))}/{total}]")

    log(f"   📦 第一轮完成: 成功 {len(batch_results)}/{total}")

    # 第二轮: 多源轮询
    remaining = [ip for ip in all_ips if ip not in batch_results]
    if remaining:
        log(f"   🔄 第二轮: 多源轮询剩余 {len(remaining)} 个...")
        checker = HostingChecker()

        def check_one(ip):
            return ip, checker.check(ip)

        with ThreadPoolExecutor(max_workers=HOSTING_CHECK_WORKERS) as executor:
            futures = {executor.submit(check_one, ip): ip for ip in remaining}
            done = 0
            for future in as_completed(futures):
                done += 1
                ip, result = future.result()
                if result:
                    batch_results[ip] = result
                if done % 20 == 0 or done == len(remaining):
                    log(f"      多源轮询进度: [{done}/{len(remaining)}]")

    # 归类
    non_hosting, hosting, failed = [], [], []
    for ip, port, region in ip_port_region_list:
        result = batch_results.get(ip)
        if result is None:
            failed.append((ip, port, region))
        elif result["is_hosting"]:
            hosting.append((ip, port, region))
        else:
            non_hosting.append((ip, port, region))

    log(f"\n   ✅ 检测完成: 非机房={len(non_hosting)} | 机房={len(hosting)} | 失败={len(failed)}")
    return non_hosting, hosting, failed


# ================= 主程序 =================

def main():
    if not BASE_DOMAIN:
        log("❌ 错误: 请先设置环境变量 BASE_DOMAIN")
        return

    log(f"🚀 开始运行")
    log(f"   基础域名: {BASE_DOMAIN}")
    log(f"   目标地区: {', '.join(sorted(ALLOWED_REGIONS))}")
    log(f"   域名源每地区: {DOMAIN_TOP_N} 个（非机房）")
    log(f"   订阅+网络每地区: {FINAL_TOP_N} 个（非机房）")

    # 分开收集
    domain_candidates = []       # (ip, port)
    sub_candidates = []          # (ip, port)
    online_by_region = {r: [] for r in ALLOWED_REGIONS}  # {region: [(ip, port)]}

    # ===== 阶段1: 提取IP =====
    log("\n" + "=" * 55)
    log("📡 阶段1: 从各源提取IP")
    log("=" * 55)

    # 1a. 域名源
    for src, typ in SOURCES:
        if typ == "DOMAIN":
            resolved = resolve_domain(src)
            for ip in resolved:
                domain_candidates.append((ip, "443"))
            log(f"   [域名] {src} -> {len(resolved)} 个IP")

    # 1b. 订阅源
    for src, typ in SOURCES:
        if typ == "SUB":
            try:
                resp = requests.get(src, timeout=15)
                resp.raise_for_status()
                content = safe_b64decode(resp.text) or resp.text
                parsed = parse_sub_content(content)
                sub_candidates.extend(parsed)
                log(f"   [订阅] {src[:55]}... -> {len(parsed)} 个IP")
            except Exception as e:
                log(f"   [订阅] {src[:55]}... -> 失败: {e}")

    # 1c. 网络文件源（直接带地区标记，不需要地区验证）
    log(f"\n   --- 网络文件源（已含地区标记，跳过地区验证）---")
    for url in ONLINE_IP_FILES:
        region_ips = fetch_online_ips(url)
        for region in ALLOWED_REGIONS:
            online_by_region[region].extend(region_ips.get(region, []))

    # 各源内部去重
    domain_candidates = list(set(domain_candidates))
    sub_candidates = list(set(sub_candidates))
    for r in ALLOWED_REGIONS:
        online_by_region[r] = list(set(online_by_region[r]))

    online_total = sum(len(v) for v in online_by_region.values())
    log(f"\n📊 提取完成:")
    log(f"   域名源:    {len(domain_candidates)} 个IP（需地区验证）")
    log(f"   订阅源:    {len(sub_candidates)} 个IP（需地区验证）")
    log(f"   网络文件:  {online_total} 个IP（已有地区标记，跳过验证）")

    # ===== 阶段2: 地区验证（仅域名源+订阅源） =====
    log("\n" + "=" * 55)
    log("🌍 阶段2: 地区验证（仅域名源+订阅源）")
    log("=" * 55)

    verified_pools = {r: {"DOMAIN": [], "SUB": []} for r in ALLOWED_REGIONS}

    all_to_check = []
    for ip, port in domain_candidates:
        all_to_check.append((ip, port, "DOMAIN"))
    for ip, port in sub_candidates:
        all_to_check.append((ip, port, "SUB"))

    all_to_check = list(set(all_to_check))
    total_check = len(all_to_check)

    if total_check > 0:
        def process_region(ip, port, source_type):
            region = check_region(ip, port)
            if region in ALLOWED_REGIONS:
                if source_type == "DOMAIN":
                    if is_ip_in_allowed_subnets(ip, region):
                        return region, ip, port, source_type
                else:
                    return region, ip, port, source_type
            return None

        checked = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(process_region, ip, port, st): (ip, port, st)
                for ip, port, st in all_to_check
            }
            for f in as_completed(futures):
                checked += 1
                res = f.result()
                if res:
                    region, ip, port, st = res
                    verified_pools[region][st].append((ip, port))
                if checked % 50 == 0 or checked == total_check:
                    log(f"   地区验证进度: [{checked}/{total_check}]")

        log(f"\n   地区验证结果:")
        for region in sorted(ALLOWED_REGIONS):
            pool = verified_pools[region]
            log(f"   {region}: 域名={len(pool['DOMAIN'])}, 订阅={len(pool['SUB'])}")
    else:
        log("   无需地区验证的IP")

    # ===== 阶段3: 合并订阅源和网络文件源 + 去重 + 机房IP筛选 =====
    log("\n" + "=" * 55)
    log("🏢 阶段3: 合并去重 + 机房IP筛选（所有源）")
    log("=" * 55)

    # 构建统一的待检测列表: (ip, port, region, source_type)
    all_for_hosting = []

    # 域名源
    for region in ALLOWED_REGIONS:
        for ip, port in verified_pools[region]["DOMAIN"]:
            all_for_hosting.append((ip, port, region, "DOMAIN"))

    # 订阅源 + 网络文件源合并去重
    # 先按地区合并
    merged_sub_online = {r: set() for r in ALLOWED_REGIONS}

    for region in ALLOWED_REGIONS:
        # 订阅源（已通过地区验证的）
        for ip, port in verified_pools[region]["SUB"]:
            merged_sub_online[region].add((ip, port))
        # 网络文件源（已有地区标记的）
        for ip, port in online_by_region[region]:
            merged_sub_online[region].add((ip, port))

    log(f"\n   订阅+网络合并去重后:")
    for region in sorted(ALLOWED_REGIONS):
        count = len(merged_sub_online[region])
        log(f"   {region}: {count} 个IP")
        for ip, port in merged_sub_online[region]:
            all_for_hosting.append((ip, port, region, "SUB_ONLINE"))

    # 全部去重
    all_for_hosting = list(set(all_for_hosting))
    log(f"\n   总计待检测: {len(all_for_hosting)} 个IP")

    if all_for_hosting:
        check_list = [(ip, port, region) for ip, port, region, st in all_for_hosting]
        non_hosting_raw, hosting_raw, failed_raw = batch_check_hosting(check_list)

        non_hosting_set = set((ip, port, region) for ip, port, region in non_hosting_raw)

        # 按地区和来源归类非机房IP
        non_hosting_pools = {r: {"DOMAIN": [], "SUB_ONLINE": []} for r in ALLOWED_REGIONS}
        for ip, port, region, st in all_for_hosting:
            if (ip, port, region) in non_hosting_set:
                non_hosting_pools[region][st].append((ip, port))

        log(f"\n   非机房IP按地区和来源:")
        for region in sorted(ALLOWED_REGIONS):
            pool = non_hosting_pools[region]
            log(f"   {region}: 域名={len(pool['DOMAIN'])}, 订阅+网络={len(pool['SUB_ONLINE'])}")
    else:
        non_hosting_pools = {r: {"DOMAIN": [], "SUB_ONLINE": []} for r in ALLOWED_REGIONS}
        log("   没有需要检测的IP")

    # ===== 阶段4: 最终筛选与输出 =====
    log("\n" + "=" * 55)
    log("📝 阶段4: 最终筛选与输出")
    log("=" * 55)

    domain_final = []
    other_final = []

    for region in sorted(ALLOWED_REGIONS):
        log(f"\n🌍 地区: {region}")

        # 域名源: 非机房池随机抽取
        d_pool = non_hosting_pools[region]["DOMAIN"]
        d_select = random.sample(d_pool, min(len(d_pool), DOMAIN_TOP_N))
        if d_select:
            update_cf_dns(region, [x[0] for x in d_select])
            for ip, port in d_select:
                domain_final.append(f"{ip}#{region}")
            log(f"   [域名源] 抽取 {len(d_select)} 个非机房IP -> domain_ips.txt")
        else:
            log(f"   [域名源] 无可用非机房IP")

        # 订阅+网络: 非机房池随机抽取
        o_pool = list(set(non_hosting_pools[region]["SUB_ONLINE"]))
        o_select = random.sample(o_pool, min(len(o_pool), FINAL_TOP_N))
        if o_select:
            for ip, port in o_select:
                other_final.append(f"{ip}:{port}#{region}")
            log(f"   [订阅+网络] 抽取 {len(o_select)} 个非机房IP -> other_ips.txt")
        else:
            log(f"   [订阅+网络] 无可用非机房IP")

    # ===== 阶段5: 写入文件 =====
    log("\n" + "=" * 55)
    log("💾 阶段5: 写入文件")
    log("=" * 55)

    with open("domain_ips.txt", "w") as f:
        f.write("\n".join(domain_final))
    log(f"   domain_ips.txt: {len(domain_final)} 条")

    with open("other_ips.txt", "w") as f:
        f.write("\n".join(other_final))
    log(f"   other_ips.txt:  {len(other_final)} 条")

    log("\n" + "=" * 55)
    log("✅ 全部任务完成！")
    log("=" * 55)
    log(f"   domain_ips.txt: {len(domain_final)} 条 (域名源，已过滤机房IP)")
    log(f"   other_ips.txt:  {len(other_final)} 条 (订阅+网络，已合并去重+过滤机房IP)")

    log("\n📋 最终结果预览:")
    log("\n   --- domain_ips.txt ---")
    for line in domain_final:
        log(f"   {line}")
    log("\n   --- other_ips.txt ---")
    for line in other_final:
        log(f"   {line}")


if __name__ == "__main__":
    main()
