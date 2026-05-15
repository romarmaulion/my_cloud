import requests
import base64
import json
import os
import random
import time
from collections import defaultdict

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
ALLOWED_REGIONS = {
    "HK",
    "JP",
    "SG",
    "KR",
    "TW",
    "US"
}

# IP段过滤
# 留空 = 不过滤
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
    "User-Agent": "Mozilla/5.0"
}


# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)


def ip_match_region(ip, region):

    prefixes = ALLOWED_IP_PREFIX.get(region)

    # 留空 = 不过滤
    if not prefixes:
        return True

    return any(
        ip.startswith(p)
        for p in prefixes
    )


def safe_b64decode(data):

    try:

        data = data.strip()

        padding = 4 - len(data) % 4

        if padding != 4:
            data += "=" * padding

        return base64.b64decode(data).decode(
            "utf-8",
            errors="ignore"
        )

    except:
        return None


def parse_node_link(line):

    line = line.strip()

    if not line:
        return None

    # vmess
    if line.startswith("vmess://"):

        try:

            raw = line[8:]

            decoded = safe_b64decode(raw)

            if not decoded:
                return None

            obj = json.loads(decoded)

            return (
                obj.get("add"),
                str(obj.get("port", "443"))
            )

        except:
            return None

    # 通用协议
    if "://" in line:

        try:

            body = line.split("#")[0]

            after = body.split("://", 1)[1]

            if "@" in after:
                after = after.rsplit("@", 1)[1]

            host_port = after.split("/")[0].split("?")[0]

            if ":" in host_port:
                host, port = host_port.split(":", 1)
            else:
                host = host_port
                port = "443"

            return host, port

        except:
            return None

    return None


# ================= ProxyIP 核心 =================

def fetch_proxyip_backend(domain):

    """
    重复请求 API
    获取多个真实后端节点
    """

    results = set()

    for _ in range(20):

        try:

            resp = requests.get(
                CHECK_API,
                params={
                    "target": domain
                },
                headers=HEADERS,
                timeout=20
            )

            data = resp.json()

            # 兼容不同返回格式
            targets = []

            if isinstance(data, dict):

                # 新版
                if "results" in data:
                    targets = data["results"]

                elif "data" in data:
                    targets = data["data"]

                elif "targets" in data:
                    targets = data["targets"]

            elif isinstance(data, list):

                targets = data

            for item in targets:

                if not isinstance(item, dict):
                    continue

                ip = item.get("ip")
                port = str(item.get("port", "443"))

                region = (
                    item.get("country")
                    or item.get("region")
                    or ""
                ).upper()

                if not ip:
                    continue

                if region not in ALLOWED_REGIONS:
                    continue

                if not ip_match_region(ip, region):
                    continue

                results.add(
                    (ip, port, region)
                )

        except:
            pass

        time.sleep(0.3)

    return list(results)


# ================= Cloudflare =================

def update_cloudflare_dns(region, ips):

    if not ips:
        return

    record_name = (
        f"{region.lower()}.{BASE_DOMAIN}"
    )

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    base_url = (
        f"https://api.cloudflare.com/client/v4/"
        f"zones/{CF_ZONE_ID}/dns_records"
    )

    log(f"\n[CF] 更新 {record_name}")

    try:

        # 删除旧记录
        old = requests.get(
            base_url,
            headers=headers,
            params={"name": record_name},
            timeout=15
        ).json()

        if old.get("success"):

            for rec in old.get("result", []):

                requests.delete(
                    f"{base_url}/{rec['id']}",
                    headers=headers,
                    timeout=15
                )

        # 添加新记录
        for ip in ips:

            payload = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }

            requests.post(
                base_url,
                headers=headers,
                json=payload,
                timeout=15
            )

            log(f"   -> {ip}")

    except Exception as e:

        log(f"[!] CF 更新失败: {e}")


# ================= 主流程 =================

def main():

    log("=" * 60)
    log("🚀 ProxyIP 自动更新开始")
    log("=" * 60)

    region_result = defaultdict(set)

    # ================= 获取 ProxyIP =================

    for domain in PROXYIP_DOMAINS:

        log(f"\n🌐 {domain}")

        results = fetch_proxyip_backend(domain)

        if not results:

            log("   -> 无结果")

            continue

        for ip, port, region in results:

            log(
                f"   -> {ip}:{port} [{region}]"
            )

            # 保存 IP:PORT
            region_result[region].add(
                (ip, port)
            )

    # ================= 更新 DNS =================

    domain_output_lines = []

    for region in sorted(region_result.keys()):

        items = list(region_result[region])

        random.shuffle(items)

        selected = items[:TOP_N]

        # DNS只能保存IP
        unique_ips = list(set(
            ip for ip, port in selected
        ))

        update_cloudflare_dns(
            region,
            unique_ips
        )

        # 文件保存 IP:PORT
        for ip, port in selected:

            domain_output_lines.append(
                f"{ip}:{port}#{region}"
            )

    # ================= 解析订阅 =================

    sub_result = set()

    for sub in SUB_SOURCES:

        log(f"\n📥 订阅解析")

        try:

            resp = requests.get(
                sub,
                headers=HEADERS,
                timeout=20
            )

            content = resp.text

            decoded = safe_b64decode(content)

            lines = (
                decoded.splitlines()
                if decoded
                else content.splitlines()
            )

            for line in lines:

                parsed = parse_node_link(line)

                if not parsed:
                    continue

                host, port = parsed

                sub_result.add(
                    f"{host}:{port}"
                )

        except Exception as e:

            log(f"[!] 订阅失败: {e}")

    # ================= 保存 =================

    with open(
        "domain_ips.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(sorted(domain_output_lines))
        )

    with open(
        "other_ips.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(sorted(sub_result))
        )

    log("\n🎉 完成")


if __name__ == "__main__":
    main()
