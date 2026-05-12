import requests
import base64
import json
import re
import socket
import dns.resolver
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import subprocess
import threading
import urllib.parse

# ================= 配置区域 =================
SOURCES = [
    ("ProxyIP.HK.CMLiussss.net", "SINGLE"),
    ("ProxyIP.JP.CMLiussss.net", "SINGLE"),
    ("sjc.o00o.ooo", "LB"),
    ("tw.william.us.ci", "MIXED"),
    ("proxy.xinyitang.dpdns.org", "LB"),
    
    ("https://sub.xinyitang.dpdns.org/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://sub.cmliussss.net/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://owo.o00o.ooo/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
    ("https://cm.soso.edu.kg/sub?host=qq.romarmaulion.ccwu.cc&uuid=d074c173-ab5e-4c1a-817f-819afbdf36b8&path=/", "SUB"),
]

DOMAIN_REGION_HINT = {
    "ProxyIP.HK.CMLiussss.net": ("HK", "SINGLE"),
    "ProxyIP.JP.CMLiussss.net": ("JP", "SINGLE"),
    "sjc.o00o.ooo":             ("US", "MIXED"),
    "tw.william.us.ci":         ("TW", "MIXED"),
    "proxy.xinyitang.dpdns.org":("UN", "LB"),
}

ALLOWED_REGIONS = {"HK", "JP", "SG", "TW", "US"}
TOP_N = 5
CHECK_API = "https://api.090227.xyz/check"

CF_API_TOKEN   = os.getenv("CF_API_TOKEN")
CF_ZONE_ID     = os.getenv("CF_ZONE_ID")
CF_BASE_DOMAIN = os.getenv("CF_BASE_DOMAIN")

CUSTOM_DOMAIN_MAP = {
    "HK": os.getenv("CF_RECORD_HK"),
    "SG": os.getenv("CF_RECORD_SG"),
    "US": os.getenv("CF_RECORD_US"),
    "JP": os.getenv("CF_RECORD_JP"),
    "TW": os.getenv("CF_RECORD_TW"),
}

PUBLIC_DNS_SERVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "9.9.9.9",
    "114.114.114.114",
    "119.29.29.29",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "v2rayNG/1.8.5",
]

# ===========================================


class CloudflareBypassHTTPClient:
    """支持Cloudflare绕过的HTTP客户端"""
    
    def __init__(self):
        self.user_agent_idx = 0
    
    def _get_user_agent(self):
        ua = USER_AGENTS[self.user_agent_idx % len(USER_AGENTS)]
        self.user_agent_idx += 1
        return ua
    
    def _fetch_with_requests(self, url, timeout=20):
        """用requests尝试（可能被CF拦截）"""
        try:
            headers = {
                "User-Agent": self._get_user_agent(),
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Sec-Ch-Ua": '"Chromium";v="91", " Not;A Brand";v="99"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
            
            session = requests.Session()
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            return resp.text if resp.status_code == 200 else None
        except Exception:
            return None
    
    def _fetch_with_curl(self, url, timeout=20):
        """用curl绕过CF（推荐）"""
        try:
            cmd = [
                "curl",
                "-s",
                "-L",
                "-A", self._get_user_agent(),
                "-b", "/tmp/cookies.txt",
                "-c", "/tmp/cookies.txt",
                "--compressed",
                "--max-time", str(timeout),
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None
    
    def _fetch_with_wget(self, url, timeout=20):
        """用wget备选"""
        try:
            cmd = [
                "wget",
                "-q",
                "-O", "-",
                "-U", self._get_user_agent(),
                "--save-cookies=/tmp/cookies.txt",
                "--keep-session-cookies",
                "--timeout=" + str(timeout),
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None
    
    def fetch(self, url):
        """多方法获取，优先级：curl > wget > requests"""
        
