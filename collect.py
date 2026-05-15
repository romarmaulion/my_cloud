import requests
import base64
import json
import os
import random
import time
from collections import defaultdict
import re
from urllib.parse import urlparse, parse_qs
import sys
import traceback

# ================= GitHub Actions 专用环境变量处理 =================
def get_github_env_var(var_name, required=False, default=None):
    """
    专门处理GitHub Actions环境变量
    支持多种获取方式，解决GitHub Actions环境变量问题
    """
    # 尝试从环境变量获取
    value = os.environ.get(var_name)
    if value and value.strip():
        return value.strip()
    
    # 尝试从GitHub Secrets格式获取
    secrets_var_name = f"SECRETS_{var_name}"
    value = os.environ.get(secrets_var_name)
    if value and value.strip():
        return value.strip()
    
    # 尝试从INPUT_前缀获取
    input_var_name = f"INPUT_{var_name.upper()}"
    value = os.environ.get(input_var_name)
    if value and value.strip():
        return value.strip()
    
    # 尝试常见变体
    common_variants = [
        var_name.upper(),
        var_name.lower(),
        f"GITHUB_SECRET_{var_name.upper()}",
        f"ACTIONS_SECRET_{var_name.upper()}",
        f"CF_{var_name.upper()}"
    ]
    
    for variant in common_variants:
        value = os.environ.get(variant)
        if value and value.strip():
            return value.strip()
    
    # 如果是必需的变量且没有找到，显示详细错误
    if required:
        error_msg = f"❌ 缺少必需的环境变量: {var_name}"
        print(f"::error::{error_msg}", flush=True)
        
        # 提供设置指导
        print(f"""
::group::🔧 环境变量设置指南
请在GitHub仓库中设置以下Secrets:

1. 访问: {os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY', 'your-repo')}/settings/secrets/actions
2. 添加以下Repository Secrets:

   🔑 名称           🔑 值示例
   ────────────────────────────────────────────────────────
   BASE_DOMAIN       your-domain.com
   CF_API_TOKEN      your_cloudflare_api_token
   CF_ZONE_ID        your_cloudflare_zone_id

3. 保存后重新运行Action
::endgroup::
        """, flush=True)
        
        # 显示当前找到的相关环境变量
        print("\n🔍 当前找到的相关环境变量:", flush=True)
        found_any = False
        relevant_keys = []
        for key in sorted(os.environ.keys()):
            key_lower = key.lower()
            if any(x in key_lower for x in ['cf_', 'base_', 'token', 'zone', 'domain', 'secret', 'input']):
                relevant_keys.append(key)
                found_any = True
        
        if found_any:
            for key in relevant_keys[:10]:  # 只显示前10个
                value = os.environ[key]
                value_preview = value[:30] + '...' if len(value) > 30 else value
                print(f"   ✅ {key} = {value_preview}", flush=True)
            if len(relevant_keys) > 10:
                print(f"   ... 还有 {len(relevant_keys) - 10} 个相关变量", flush=True)
        else:
            print("   ❌ 未找到任何相关的环境变量", flush=True)
        
        sys.exit(1)
    
    return default


# ================= 配置加载 =================
def load_config():
    """加载配置，专门处理GitHub Actions环境"""
    print("🚀 开始加载配置...", flush=True)
    
    # 获取必需的环境变量
    BASE_DOMAIN = get_github_env_var("BASE_DOMAIN", required=True)
    CF_API_TOKEN = get_github_env_var("CF_API_TOKEN", required=True)
    CF_ZONE_ID = get_github_env_var("CF_ZONE_ID", required=True)
    
    print(f"✅ 配置加载成功:", flush=True)
    print(f"   🌐 BASE_DOMAIN: {BASE_DOMAIN}", flush=True)
    print(f"   🔑 CF_API_TOKEN: {'*' * (len(CF_API_TOKEN) - 4) + CF_API_TOKEN[-4:]}", flush=True)
    print(f"   🆔 CF_ZONE_ID: {CF_ZONE_ID[:8]}...", flush=True)
    
    return {
        "BASE_DOMAIN": BASE_DOMAIN,
        "CF_API_TOKEN": CF_API_TOKEN,
        "CF_ZONE_ID": CF_ZONE_ID
    }

# 加载配置
try:
    CONFIG = load_config()
    BASE_DOMAIN = CONFIG["BASE_DOMAIN"]
    CF_API_TOKEN = CONFIG["CF_API_TOKEN"]
    CF_ZONE_ID = CONFIG["CF_ZONE_ID"]
except Exception as e:
    print(f"❌ 配置加载失败: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

# ================= 动态配置 =================
# ProxyIP 域名
PROXYIP_DOMAINS = [
    "tw.william.us.ci",
    "jp.cle.us.ci",
    "sg.cle.us.ci",
    "ProxyIP.JP.CMLiussss.net",
    "ProxyIP.KR.CMLiussss.net",
]

# 订阅源 - 从环境变量获取
SUB_SOURCES_ENV = os.environ.get("SUB_SOURCES", "").strip()
SUB_SOURCES = [url.strip() for url in SUB_SOURCES_ENV.splitlines() if url.strip()] or [
    "https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/",
]

# 每地区随机保留数量
try:
    TOP_N = int(os.environ.get("TOP_N", "5"))
except ValueError:
    TOP_N = 5

# 允许地区
ALLOWED_REGIONS_ENV = os.environ.get("ALLOWED_REGIONS", "HK,JP,SG,KR,TW,US").strip()
ALLOWED_REGIONS = {region.strip().upper() for region in ALLOWED_REGIONS_ENV.split(",") if region.strip()}

# ProxyIP API
CHECK_API = os.environ.get("CHECK_API", "https://check.proxyip.cmliussss.net/api/check")

# IP段过滤配置
IP_PREFIXES = {}
ip_prefixes_env = os.environ.get("IP_PREFIXES", "").strip()
if ip_prefixes_env:
    for line in ip_prefixes_env.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        region_part, prefixes_part = line.split(":", 1)
        region = region_part.strip().upper()
        prefix_list = [p.strip() for p in prefixes_part.split(",") if p.strip()]
        if region and prefix_list:
            IP_PREFIXES[region] = prefix_list

# 调试模式
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() in ["true", "1", "yes"]

print(f"\n📋 运行配置:", flush=True)
print(f"   🎯 ProxyIP域名数量: {len(PROXYIP_DOMAINS)}", flush=True)
print(f"   📡 订阅源数量: {len(SUB_SOURCES)}", flush=True)
print(f"   🌍 允许地区: {', '.join(sorted(ALLOWED_REGIONS))}", flush=True)
print(f"   📊 每地区保留: {TOP_N} 个节点", flush=True)
print(f"   🔍 IP前缀过滤: {'已配置' if IP_PREFIXES else '未配置'}", flush=True)
print(f"   🐞 调试模式: {'启用' if DEBUG_MODE else '禁用'}", flush=True)
print("-" * 60, flush=True)

# ================= 工具函数 =================

def log(msg, level="INFO"):
    """增强日志功能，适配GitHub Actions"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # GitHub Actions特殊日志格式
    if level == "ERROR":
        print(f"::error::{msg}", flush=True)
    elif level == "WARNING":
        print(f"::warning::{msg}", flush=True)
    
    # 标准输出
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
    if DEBUG_MODE:
        log(msg, "DEBUG")


def ip_match_region(ip, region):
    """检查IP是否符合地区前缀规则"""
    prefixes = IP_PREFIXES.get(region, [])
    
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
            parts = line[5:].split('@', 1)
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
                timeout=30
            )
            
            # 检查HTTP状态码
            if resp.status_code != 200:
                log(f"❌ API返回状态码: {resp.status_code}", "ERROR")
                debug_log(f"响应内容: {resp.text[:200]}...")
                time.sleep(2)
                continue
            
            data = resp.json()
            debug_log(f"API原始响应: {json.dumps(data, indent=2)[:500]}...")
            
            # 智能解析不同格式的响应
            targets = []
            
            if isinstance(data, dict):
                if data.get("code") in [0, 200, 20000]:
                    if "data" in data and isinstance(data["data"], list):
                        targets = data["data"]
                    elif "results" in data and isinstance(data["results"], list):
                        targets = data["results"]
                    elif "targets" in data and isinstance(data["targets"], list):
                        targets = data["targets"]
                    elif "nodes" in data and isinstance(data["nodes"], list):
                        targets = data["nodes"]
                else:
                    msg = data.get("msg", data.get("message", "未知错误"))
                    log(f"❌ API返回错误码: {data.get('code')}, 消息: {msg}", "ERROR")
            elif isinstance(data, list):
                targets = data
            
            # 尝试查找包含节点信息的字段
            if not targets:
                for key in ["data", "results", "targets", "nodes", "items", "list", "proxies"]:
                    if key in data and isinstance(data[key], list):
                        targets = data[key]
                        break
            
            debug_log(f"解析到 {len(targets)} 个目标节点")
            
            if not targets:
                log("   -> 未找到节点数据", "WARNING")
                continue
            
            # 处理节点
            valid_count = 0
            for item in targets:
                try:
                    if not isinstance(item, dict):
                        continue
                    
                    # 获取IP
                    ip = None
                    for field in ["ip", "address", "host", "server", "hostname"]:
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
                    for field in ["port", "server_port", "local_port"]:
                        if field in item and item[field]:
                            try:
                                port = str(int(item[field]))
                            except (ValueError, TypeError):
                                continue
                            break
                    
                    # 获取地区
                    region = ""
                    for field in ["country", "region", "location", "geo", "country_code"]:
                        if field in item and item[field]:
                            region_val = str(item[field]).strip()
                            # 只取前2个字符作为地区代码
                            region = region_val[:2].upper()
                            break
                    
                    # 验证地区
                    if region not in ALLOWED_REGIONS:
                        debug_log(f"地区 {region} 不在允许列表中，跳过")
                        continue
                    
                    # IP段过滤
                    if not ip_match_region(ip, region):
                        continue
                    
                    results.add((ip, port, region))
                    valid_count += 1
                    debug_log(f"✅ 找到节点: {ip}:{port} [{region}]")
                    
                except Exception as e:
                    debug_log(f"处理节点时出错: {e}, 节点数据: {item}")
            
            debug_log(f"本次尝试找到 {valid_count} 个有效节点")
            
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
            debug_log(f"响应内容: {resp.text[:200]}...")
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
                debug_log(f"响应: {response.text}")
                return
            
            data = response.json()
            if not data.get("success"):
                errors = data.get("errors", [])
                log(f"❌ Cloudflare API错误: {errors}", "ERROR")
                return
            
            records = data.get("result", [])
            existing_records.extend(records)
            
            # 检查是否还有更多页面
            result_info = data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages:
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
                        debug_log(f"响应: {del_resp.text}")
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
                debug_log(f"响应: {add_resp.text}")
            
            time.sleep(1)  # 避免速率限制
        
        log(f"   ✅ 成功更新 {added_count}/{len(ips)} 个记录")
        
    except Exception as e:
        log(f"❌ Cloudflare 更新失败: {e}", "ERROR")
        debug_log(f"堆栈跟踪: {traceback.format_exc()}")


# ================= 订阅解析 =================

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
                timeout=30
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
                    node_str = f"{host}:{port}"
                    sub_result.add(node_str)
                    valid_nodes += 1
            
            log(f"   ✅ 找到 {valid_nodes} 个有效节点")
            
        except Exception as e:
            log(f"❌ 订阅解析失败: {e}", "ERROR")
            debug_log(f"堆栈跟踪: {traceback.format_exc()}")
    
    return sub_result


# ================= 主流程 =================

def main():
    """主函数"""
    start_time = time.time()
    
    print("=" * 60, flush=True)
    print("🚀 ProxyIP 自动更新开始", flush=True)
    print(f"⏰ 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print("=" * 60, flush=True)
    
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
        if domain_output_lines:
            with open("domain_ips.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(domain_output_lines)))
            log(f"💾 已保存 {len(domain_output_lines)} 个ProxyIP节点到 domain_ips.txt")
        
        # 保存订阅节点
        if sub_result:
            with open("other_ips.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(sub_result)))
            log(f"💾 已保存 {len(sub_result)} 个订阅节点到 other_ips.txt")
        
    except Exception as e:
        log(f"❌ 保存文件失败: {e}", "ERROR")
        debug_log(f"堆栈跟踪: {traceback.format_exc()}")
    
    # ================= 完成信息 =================
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 60, flush=True)
    print("🎉 所有任务完成！", flush=True)
    print(f"⏱️  总耗时: {duration:.2f} 秒", flush=True)
    print(f"📈 最终统计:", flush=True)
    for region, nodes in sorted(region_result.items()):
        print(f"   {region}: {len(nodes)} 个节点", flush=True)
    print(f"   订阅节点: {len(sub_result)} 个", flush=True)
    print("=" * 60, flush=True)


# ================= 全局变量 =================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
}

# ================= 执行入口 =================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 程序被用户中断", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 严重错误: {e}", file=sys.stderr, flush=True)
        print(f"堆栈跟踪: {traceback.format_exc()}", file=sys.stderr, flush=True)
        sys.exit(1)
