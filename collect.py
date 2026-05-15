import requests
import base64
import json
import os
import random
import time
from collections import defaultdict
import re
from urllib.parse import urlparse, parse_qs

# ================= 配置验证 =================
def validate_config():
    """验证必要配置是否存在"""
    required_vars = {
        "BASE_DOMAIN": os.getenv("CF_BASE_DOMAIN"),
        "CF_API_TOKEN": os.getenv("CF_API_TOKEN"),
        "CF_ZONE_ID": os.getenv("CF_ZONE_ID")
    }
    
    missing = [var for var, value in required_vars.items() if not value]
    if missing:
        raise ValueError(f"缺少必要环境变量: {', '.join(missing)}")
    
    return required_vars

# ================= 配置 =================
try:
    config = validate_config()
    BASE_DOMAIN = config["CF_BASE_DOMAIN"]
    CF_API_TOKEN = config["CF_API_TOKEN"]
    CF_ZONE_ID = config["CF_ZONE_ID"]
except ValueError as e:
    print(f"❌ 配置错误: {e}")
    print("请设置以下环境变量:")
    print("  - BASE_DOMAIN: 您的主域名")
    print("  - CF_API_TOKEN: Cloudflare API Token")
    print("  - CF_ZONE_ID: Cloudflare Zone ID")
    exit(1)

# ProxyIP 域名
PROXYIP_DOMAINS = [
    "tw.william.us.ci",
    "tw.william.us.ci",
    "ProxyIP.SG.CMLiussss.net",
    "ProxyIP.JP.CMLiussss.net",
    "ProxyIP.HK.CMLiussss.net",
    "sjc.o00o.ooo",
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
}


# ================= 工具函数 =================

def log(msg, level="INFO"):
    """增强日志功能，带时间戳和级别"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    level_color = {
        "INFO": "\033[32m",    # 绿色
        "WARNING": "\033[33m", # 黄色
        "ERROR": "\033[31m",   # 红色
        "DEBUG": "\033[36m"    # 青色
    }
    reset = "\033[0m"
    color = level_color.get(level, "")
    print(f"{timestamp} {color}[{level}] {msg}{reset}", flush=True)


def debug_log(msg):
    """调试日志"""
    if os.getenv("DEBUG", "false").lower() in ["true", "1", "yes"]:
        log(msg, "DEBUG")


def ip_match_region(ip, region):
    """检查IP是否符合地区前缀规则"""
    prefixes = ALLOWED_IP_PREFIX.get(region, [])
    
    # 留空 = 不过滤
    if not prefixes:
        return True
    
    for prefix in prefixes:
        if ip.startswith(prefix):
            return True
    
    debug_log(f"IP {ip} 不符合 {region} 的前缀规则: {prefixes}")
    return False


def safe_b64decode(data):
    """安全的Base64解码"""
    try:
        data = data.strip()
        
        # 移除URL安全字符
        data = data.replace("-", "+").replace("_", "/")
        
        # 添加必要的填充
        padding = len(data) % 4
        if padding:
            data += "=" * (4 - padding)
        
        decoded = base64.b64decode(data, validate=True)
        return decoded.decode('utf-8', errors='ignore')
        
    except Exception as e:
        debug_log(f"Base64解码失败: {e} - 数据: {data[:50]}...")
        return None


def extract_ip_port_from_url(url):
    """从URL中提取IP和端口"""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        if not netloc:
            return None
        
        # 处理 [ipv6]:port 格式
        if netloc.startswith('[') and ']' in netloc:
            host_part, port_part = netloc.rsplit(']', 1)
            host = host_part[1:]  # 移除开头的 [
            port = port_part[1:] if port_part.startswith(':') else "443"
        elif ':' in netloc:
            host, port = netloc.split(':', 1)
        else:
            host = netloc
            port = "443"
        
        # 验证IP格式
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) or ':' in host:
            return host, port
        
        return None
        
    except Exception as e:
        debug_log(f"URL解析失败: {e} - URL: {url}")
        return None


def parse_node_link(line):
    """解析节点链接，支持多种格式"""
    line = line.strip()
    if not line:
        return None
    
    try:
        # VMess 格式
        if line.startswith("vmess://"):
            raw = line[8:]
            decoded = safe_b64decode(raw)
            if decoded:
                try:
                    obj = json.loads(decoded)
                    host = obj.get("add") or obj.get("address")
                    port = str(obj.get("port", "443"))
                    if host and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                        return host, port
                except json.JSONDecodeError:
                    pass
        
        # VLESS 格式
        elif line.startswith("vless://"):
            parsed = urlparse(line)
            if parsed.hostname and parsed.port:
                return parsed.hostname, str(parsed.port)
            elif parsed.hostname:
                query = parse_qs(parsed.query)
                port = query.get("port", ["443"])[0]
                return parsed.hostname, port
        
        # Trojan 格式
        elif line.startswith("trojan://"):
            parsed = urlparse(line)
            if parsed.hostname and parsed.port:
                return parsed.hostname, str(parsed.port)
            elif parsed.hostname:
                return parsed.hostname, "443"
        
        # Shadowsocks 格式
        elif line.startswith("ss://"):
            # ss://base64(method:password@host:port)
            parts = line[5:].split('@')
            if len(parts) == 2:
                server_part = parts[1].split('#')[0].split('?')[0]
                if ':' in server_part:
                    host, port = server_part.split(':', 1)
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                        return host, port
        
        # 尝试从普通URL提取
        result = extract_ip_port_from_url(line)
        if result:
            return result
        
        return None
        
    except Exception as e:
        debug_log(f"节点解析失败: {e} - 行: {line[:100]}...")
        return None


# ================= ProxyIP 核心 =================

def fetch_proxyip_backend(domain, max_retries=3):
    """
    获取ProxyIP后端节点，带重试机制
    """
    results = set()
    debug_log(f"开始获取 {domain} 的后端节点")
    
    for attempt in range(max_retries):
        try:
            log(f"📡 请求 {domain} (尝试 {attempt + 1}/{max_retries})")
            
            resp = requests.get(
                CHECK_API,
                params={"target": domain},
                headers=HEADERS,
                timeout=30,
                verify=True
            )
            
            # 检查HTTP状态码
            if resp.status_code != 200:
                log(f"❌ API返回状态码: {resp.status_code}", "ERROR")
                log(f"响应内容: {resp.text[:200]}...", "DEBUG")
                time.sleep(2)
                continue
            
            data = resp.json()
            debug_log(f"API原始响应: {json.dumps(data, indent=2)[:500]}...")
            
            # 智能解析不同格式的响应
            targets = []
            
            # 情况1: 标准格式 { "data": [...], "code": 0 }
            if isinstance(data, dict):
                if data.get("code") == 0 or data.get("code") == 200:
                    if "data" in data and isinstance(data["data"], list):
                        targets = data["data"]
                    elif "results" in data and isinstance(data["results"], list):
                        targets = data["results"]
                    elif "targets" in data and isinstance(data["targets"], list):
                        targets = data["targets"]
                    elif "nodes" in data and isinstance(data["nodes"], list):
                        targets = data["nodes"]
                else:
                    log(f"❌ API返回错误码: {data.get('code')}, 消息: {data.get('msg', '未知错误')}", "ERROR")
            
            # 情况2: 直接返回列表
            elif isinstance(data, list):
                targets = data
            
            # 情况3: 嵌套格式
            else:
                # 尝试查找包含节点信息的字段
                for key in ["data", "results", "targets", "nodes", "items", "list"]:
                    if key in data and isinstance(data[key], list):
                        targets = data[key]
                        break
            
            debug_log(f"解析到 {len(targets)} 个目标节点")
            
            if not targets:
                log("   -> 未找到节点数据", "WARNING")
                continue
            
            # 处理节点
            for item in targets:
                try:
                    if not isinstance(item, dict):
                        continue
                    
                    # 获取IP，尝试多种字段名
                    ip = None
                    for field in ["ip", "address", "host", "server"]:
                        if field in item and item[field]:
                            ip = str(item[field]).strip()
                            break
                    
                    if not ip:
                        continue
                    
                    # 验证IP格式
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        continue
                    
                    # 获取端口
                    port = "443"
                    for field in ["port", "server_port"]:
                        if field in item and item[field]:
                            try:
                                port = str(int(item[field]))
                            except (ValueError, TypeError):
                                continue
                            break
                    
                    # 获取地区
                    region = ""
                    for field in ["country", "region", "location", "geo"]:
                        if field in item and item[field]:
                            region = str(item[field]).strip().upper()
                            break
                    
                    # 简化地区代码
                    if region:
                        region = region[:2]
                    
                    # 验证地区
                    if region not in ALLOWED_REGIONS:
                        debug_log(f"地区 {region} 不在允许列表中，跳过")
                        continue
                    
                    # IP段过滤
                    if not ip_match_region(ip, region):
                        continue
                    
                    results.add((ip, port, region))
                    debug_log(f"✅ 找到节点: {ip}:{port} [{region}]")
                    
                except Exception as e:
                    debug_log(f"处理节点时出错: {e}, 节点数据: {item}")
            
            if results:
                log(f"✅ 成功获取 {len(results)} 个有效节点")
                return list(results)
            
            log("   -> 未找到有效节点", "WARNING")
            time.sleep(3)
            
        except requests.exceptions.RequestException as e:
            log(f"❌ 网络请求失败: {e}", "ERROR")
            time.sleep(3)
        except json.JSONDecodeError as e:
            log(f"❌ JSON解析失败: {e}", "ERROR")
            log(f"响应内容: {resp.text[:200]}...", "DEBUG")
            time.sleep(3)
        except Exception as e:
            log(f"❌ 未知错误: {e}", "ERROR")
            time.sleep(3)
    
    log(f"❌ 所有重试失败，无法获取 {domain} 的节点", "ERROR")
    return list(results)


# ================= Cloudflare =================

def update_cloudflare_dns(region, ips):
    """更新Cloudflare DNS记录"""
    if not ips:
        log(f"⚠️  {region} 没有IP地址，跳过DNS更新", "WARNING")
        return
    
    record_name = f"{region.lower()}.{BASE_DOMAIN}"
    log(f"\n[CF] 🔄 更新 {record_name} - {len(ips)} 个IP地址")
    
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    base_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    
    try:
        # 1. 获取现有记录
        log("   -> 获取现有DNS记录...")
        existing_records = []
        
        page = 1
        while True:
            params = {
                "name": record_name,
                "type": "A",
                "page": page,
                "per_page": 100
            }
            
            response = requests.get(
                base_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code != 200:
                log(f"❌ 获取记录失败: {response.status_code}", "ERROR")
                log(f"响应: {response.text}", "DEBUG")
                return
            
            data = response.json()
            if not data.get("success"):
                log(f"❌ Cloudflare API错误: {data.get('errors')}", "ERROR")
                return
            
            records = data.get("result", [])
            existing_records.extend(records)
            
            # 检查是否还有更多页面
            result_info = data.get("result_info", {})
            if page >= result_info.get("total_pages", 1):
                break
            page += 1
        
        log(f"   -> 找到 {len(existing_records)} 个现有记录")
        
        # 2. 删除旧记录
        if existing_records:
            log("   -> 删除旧记录...")
            for record in existing_records:
                record_id = record.get("id")
                if record_id:
                    del_resp = requests.delete(
                        f"{base_url}/{record_id}",
                        headers=headers,
                        timeout=30
                    )
                    if del_resp.status_code == 200:
                        log(f"   ✅ 删除记录 {record_id}")
                    else:
                        log(f"   ❌ 删除记录 {record_id} 失败: {del_resp.status_code}", "ERROR")
                    time.sleep(0.5)  # 避免速率限制
        
        # 3. 添加新记录
        log("   -> 添加新记录...")
        added_count = 0
        for ip in ips:
            payload = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 60,
                "proxied": False
            }
            
            add_resp = requests.post(
                base_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if add_resp.status_code == 200:
                added_count += 1
                log(f"   ✅ 添加记录: {ip}")
            else:
                log(f"   ❌ 添加记录 {ip} 失败: {add_resp.status_code}", "ERROR")
                log(f"   响应: {add_resp.text}", "DEBUG")
            
            time.sleep(1)  # 避免速率限制
        
        log(f"   ✅ 成功更新 {added_count}/{len(ips)} 个记录")
        
    except Exception as e:
        log(f"❌ Cloudflare 更新失败: {e}", "ERROR")
        import traceback
        log(f"   堆栈跟踪: {traceback.format_exc()}", "DEBUG")


# ================= 主流程 =================

def fetch_subscription_nodes():
    """获取订阅源中的节点"""
    sub_result = set()
    
    for sub_url in SUB_SOURCES:
        log(f"\n📥 解析订阅源: {sub_url}")
        
        try:
            # 获取订阅内容
            resp = requests.get(
                sub_url,
                headers=HEADERS,
                timeout=30,
                verify=True
            )
            
            if resp.status_code != 200:
                log(f"❌ 订阅请求失败: {resp.status_code}", "ERROR")
                continue
            
            content = resp.text.strip()
            
            # 尝试Base64解码
            decoded_content = safe_b64decode(content)
            if decoded_content:
                log("   -> Base64解码成功")
                lines = decoded_content.splitlines()
            else:
                log("   -> 使用原始内容")
                lines = content.splitlines()
            
            log(f"   -> 共 {len(lines)} 行内容")
            
            # 解析节点
            valid_nodes = 0
            for line in lines:
                if not line.strip():
                    continue
                
                parsed = parse_node_link(line)
                if parsed:
                    host, port = parsed
                    sub_result.add(f"{host}:{port}")
                    valid_nodes += 1
            
            log(f"   ✅ 找到 {valid_nodes} 个有效节点")
            
        except Exception as e:
            log(f"❌ 订阅解析失败: {e}", "ERROR")
            import traceback
            log(f"   堆栈跟踪: {traceback.format_exc()}", "DEBUG")
    
    return sub_result


def main():
    """主函数"""
    log("=" * 60)
    log("🚀 ProxyIP 自动更新开始")
    log(f"📋 配置信息:")
    log(f"   - 基础域名: {BASE_DOMAIN}")
    log(f"   - ProxyIP域名数量: {len(PROXYIP_DOMAINS)}")
    log(f"   - 允许地区: {', '.join(sorted(ALLOWED_REGIONS))}")
    log(f"   - 每地区保留: {TOP_N} 个节点")
    log("=" * 60)
    
    region_result = defaultdict(set)
    
    # ================= 获取 ProxyIP =================
    total_nodes = 0
    
    for domain in PROXYIP_DOMAINS:
        log(f"\n🌐 处理域名: {domain}")
        
        results = fetch_proxyip_backend(domain, max_retries=2)
        
        if not results:
            log("   -> ⚠️  无有效节点", "WARNING")
            continue
        
        log(f"   ✅ 获取到 {len(results)} 个节点")
        
        for ip, port, region in results:
            log(f"   -> {ip}:{port} [{region}]")
            region_result[region].add((ip, port))
            total_nodes += 1
    
    log(f"\n📊 汇总结果: 共 {total_nodes} 个节点，覆盖 {len(region_result)} 个地区")
    
    if not region_result:
        log("❌ 未获取到任何有效节点，程序终止", "ERROR")
        return
    
    # ================= 更新 DNS =================
    domain_output_lines = []
    
    for region in sorted(region_result.keys()):
        items = list(region_result[region])
        log(f"\n🌍 处理地区: {region} ({len(items)} 个节点)")
        
        if len(items) > TOP_N:
            random.shuffle(items)
            selected = items[:TOP_N]
            log(f"   -> 随机选择 {TOP_N} 个节点")
        else:
            selected = items
            log(f"   -> 使用全部 {len(items)} 个节点")
        
        # DNS只能保存IP
        unique_ips = list(set(ip for ip, port in selected))
        
        # 更新Cloudflare DNS
        update_cloudflare_dns(region, unique_ips)
        
        # 文件保存 IP:PORT
        for ip, port in selected:
            domain_output_lines.append(f"{ip}:{port}#{region}")
    
    # ================= 解析订阅 =================
    log(f"\n📥 获取订阅节点")
    sub_result = fetch_subscription_nodes()
    log(f"✅ 订阅节点总数: {len(sub_result)}")
    
    # ================= 保存结果 =================
    try:
        # 保存ProxyIP节点
        with open("domain_ips.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(domain_output_lines)))
        log(f"💾 已保存 {len(domain_output_lines)} 个ProxyIP节点到 domain_ips.txt")
        
        # 保存订阅节点
        with open("other_ips.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(sub_result)))
        log(f"💾 已保存 {len(sub_result)} 个订阅节点到 other_ips.txt")
        
    except Exception as e:
        log(f"❌ 保存文件失败: {e}", "ERROR")
    
    log("\n🎉 所有任务完成！")
    
    # 显示统计信息
    log("\n📈 最终统计:")
    for region, nodes in sorted(region_result.items()):
        log(f"   {region}: {len(nodes)} 个节点")
    log(f"   订阅节点: {len(sub_result)} 个")


if __name__ == "__main__":
    try:
        start_time = time.time()
        main()
        end_time = time.time()
        log(f"\n⏱️  总耗时: {end_time - start_time:.2f} 秒")
    except KeyboardInterrupt:
        log("\n🛑 程序被用户中断", "WARNING")
    except Exception as e:
        log(f"\n❌ 严重错误: {e}", "ERROR")
        import traceback
        log(f"堆栈跟踪: {traceback.format_exc()}", "DEBUG")
