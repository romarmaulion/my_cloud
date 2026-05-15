下面给你一份 ✅ **完整优化稳定版脚本**

已修复：

- ✅ ProxyIP API 多种返回格式兼容
- ✅ IP 字段多名称兼容（ip / address / host）
- ✅ Base64 URL-safe 支持
- ✅ 支持 vmess / vless / trojan / ss
- ✅ 防 API 限流
- ✅ 更清晰日志
- ✅ 不会因为 region 为空直接丢弃
- ✅ 更稳健的异常处理

你可以直接整体替换原脚本。

---

# ✅ 完整优化版脚本

```python
import requests
import base64
import json
import os
import random
import time
from collections import defaultdict

# ================= 配置 =================

BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")

PROXYIP_DOMAINS = [
    "tw.william.us.ci",
    "kr.william.us.ci",
    "sjc.o00o.ooo",
    "ProxyIP.JP.CMLiussss.net",
    "ProxyIP.HK.CMLiussss.net",
    "ProxyIP.SG.CMLiussss.net",
]

SUB_SOURCES = [
    "https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
    "https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
]

TOP_N = 5

ALLOWED_REGIONS = {"HK", "JP", "SG", "KR", "TW", "US"}

ALLOWED_IP_PREFIX = {
    "HK": ["219."],
    "JP": [],
    "SG": [],
    "KR": [],
    "TW": [],
    "US": [],
}

CHECK_API = "https://check.proxyip.cmliussss.net/api/check"

HEADERS = {"User-Agent": "Mozilla/5.0"}

# ================= 工具函数 =================

def log(msg):
    print(msg, flush=True)


def ip_match_region(ip, region):
    prefixes = ALLOWED_IP_PREFIX.get(region)
    if not prefixes:
        return True
    return any(ip.startswith(p) for p in prefixes)


def safe_b64decode(data):
    try:
        data = data.strip()
        data = data.replace("-", "+").replace("_", "/")
        padding = len(data) % 4
        if padding:
            data += "=" * (4 - padding)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None


def parse_node_link(line):
    line = line.strip()
    if not line:
        return None

    try:
        # VMESS
        if line.startswith("vmess://"):
            raw = line[8:]
            decoded = safe_b64decode(raw)
            if not decoded:
                return None
            obj = json.loads(decoded)
            return obj.get("add"), str(obj.get("port", "443"))

        # Shadowsocks
        if line.startswith("ss://"):
            body = line[5:].split("#")[0]
            if "@" not in body:
                body = safe_b64decode(body)
            if not body or "@" not in body:
                return None
            after = body.rsplit("@", 1)[1]
            host, port = after.split(":", 1)
            return host, port

        # 通用协议 vless trojan 等
        if "://" in line:
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


# ================= ProxyIP =================

def fetch_proxyip_backend(domain):
    results = set()

    for _ in range(10):
        try:
            resp = requests.get(
                CHECK_API,
                params={"target": domain},
                headers=HEADERS,
                timeout=15
            )

            if resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except:
                continue

            items = []

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                for key in ["results", "data", "targets", "result"]:
                    if key in data and isinstance(data[key], list):
                        items = data[key]
                        break

            for item in items:
                if not isinstance(item, dict):
                    continue

                ip = item.get("ip") or item.get("address") or item.get("host")
                port = str(item.get("port") or 443)
                region = (
                    item.get("country")
                    or item.get("region")
                    or item.get("country_code")
                    or ""
                ).upper()

                if not ip:
                    continue

                ip = ip.strip()

                if region and region not in ALLOWED_REGIONS:
                    continue

                if region and not ip_match_region(ip, region):
                    continue

                results.add((ip, port, region or "UNKNOWN"))

        except Exception as e:
            log(f"[API异常] {e}")

        time.sleep(0.3)

    return list(results)


# ================= Cloudflare =================

def update_cloudflare_dns(region, ips):
    if not ips or not BASE_DOMAIN:
        return

    record_name = f"{region.lower()}.{BASE_DOMAIN}"

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    log(f"\n[CF] 更新 {record_name}")

    try:
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

        for ip in ips:
            payload = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }
            requests.post(base_url, headers=headers, json=payload, timeout=15)
            log(f"   -> {ip}")

    except Exception as e:
        log(f"[CF更新失败] {e}")


# ================= 主程序 =================

def main():

    log("=" * 60)
    log("🚀 ProxyIP 自动更新开始")
    log("=" * 60)

    region_result = defaultdict(set)

    # 获取 ProxyIP
    for domain in PROXYIP_DOMAINS:
        log(f"\n🌐 查询 {domain}")
        results = fetch_proxyip_backend(domain)
        log(f"   -> 获取 {len(results)} 个结果")

        for ip, port, region in results:
            log(f"      {ip}:{port} [{region}]")
            region_result[region].add((ip, port))

    # 更新 DNS
    domain_output_lines = []

    for region in sorted(region_result.keys()):
        items = list(region_result[region])
        random.shuffle(items)
        selected = items[:TOP_N]

        unique_ips = list(set(ip for ip, port in selected))

        update_cloudflare_dns(region, unique_ips)

        for ip, port in selected:
            domain_output_lines.append(f"{ip}:{port}#{region}")

    # 解析订阅
    sub_result = set()

    for sub in SUB_SOURCES:
        log(f"\n📥 解析订阅 {sub}")
        try:
            resp = requests.get(sub, headers=HEADERS, timeout=20)
            content = resp.text

            decoded = safe_b64decode(content)
            lines = decoded.splitlines() if decoded else content.splitlines()

            for line in lines:
                parsed = parse_node_link(line)
                if not parsed:
                    continue
                host, port = parsed
                sub_result.add(f"{host}:{port}")

        except Exception as e:
            log(f"[订阅失败] {e}")

    # 保存文件
    with open("domain_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_output_lines)))

    with open("other_ips.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(sub_result)))

    log("\n🎉 完成")


if __name__ == "__main__":
    main()
```

---

# ✅ 运行后你会得到

### ✅ domain_ips.txt

```
1.2.3.4:443#JP
8.8.8.8:443#HK
```

### ✅ other_ips.txt

```
example.com:443
1.1.1.1:443
```

---

# ✅ 如果还是没有解析出 IP

请加一句：

```python
print(resp.text)
```

看 API 实际返回结构发给我，我可以再给你针对性适配。

---

如果你愿意，我还能帮你升级为：

- 🚀 多线程高速采集
- 🚀 自动测速排序
- 🚀 自动生成 Clash 配置
- 🚀 自动生成订阅接口
- 🚀 防封限流缓存机制

告诉我你的最终用途，我给你做终极版。
