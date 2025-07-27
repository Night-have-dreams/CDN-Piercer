import requests
import ssl
import socket
import base64
import mmh3
import re
from bs4 import BeautifulSoup
import tldextract

def get_favicon_hash(url):
    """自動抓 favicon，計算mmh3 hash（Shodan/CTF用）"""
    try:
        parsed = requests.utils.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        favicon_url = base + "/favicon.ico"
        resp = requests.get(favicon_url, timeout=8, verify=False)
        if resp.status_code == 200 and resp.content:
            b64 = base64.encodebytes(resp.content).decode()
            return mmh3.hash(b64)
    except Exception:
        pass
    return None

def get_title_and_server(url):
    """抓首頁title、server欄位"""
    headers = {
        "User-Agent": "Mozilla/5.0 (CDNsearch SiteCrawler)",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=8, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.string.strip() if soup.title else None
        server = resp.headers.get("Server")
        return title, server, resp.headers
    except Exception:
        return None, None, {}

def get_cert_cn(hostname, port=443):
    """取得SSL憑證CN"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return subject.get('commonName')
    except Exception:
        return None

def extract_hostname(url):
    """抓domain/hostname（自動去除http(s)等雜訊）"""
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    try:
        parsed = requests.utils.urlparse(url)
        return parsed.hostname
    except Exception:
        return None

def crawl_site_features(url):
    """
    綜合爬取目標站特徵
    回傳dict: {
        "favicon_hash": int or None,
        "title": str or None,
        "server": str or None,
        "headers": dict,
        "cert_cn": str or None,
        "hostname": str,
    }
    """
    # 標準化url
    if not url.startswith('http'):
        url = 'http://' + url
    hostname = extract_hostname(url)
    favicon_hash = get_favicon_hash(url)
    title, server, headers = get_title_and_server(url)
    cert_cn = None
    if hostname:
        cert_cn = get_cert_cn(hostname)
    return {
        "favicon_hash": favicon_hash,
        "title": title,
        "server": server,
        "headers": dict(headers),
        "cert_cn": cert_cn,
        "hostname": hostname,
    }

# 測試用
if __name__ == "__main__":
    url = input("目標網址：").strip()
    result = crawl_site_features(url)
    for k, v in result.items():
        print(f"{k:12}: {v}")
