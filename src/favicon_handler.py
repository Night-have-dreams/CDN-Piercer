import requests
import re
import os
import urllib3

# 全域禁用 HTTPS 驗證警告（適用於滲透/掃描）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_favicon_bytes_from_url(url, timeout=10, verify=False):
    """
    嘗試自動獲取 favicon，依序嘗試:
    1. https/http://domain/favicon.ico
    2. html <link rel=icon> 解析動態路徑
    返回 bytes，失敗返回 None
    """
    try:
        # 處理協定，只取主機部分
        if not url.startswith('http'):
            url = 'http://' + url
        netloc = re.sub(r'^https?://', '', url, flags=re.I).split('/')[0]

        def try_get(url):
            try:
                resp = requests.get(url, timeout=timeout, verify=verify)
                if resp.status_code == 200 and resp.content:
                    return resp.content
            except Exception:
                pass
            return None

        # Step 1: 優先嘗試 https favicon.ico
        for proto in ['https://', 'http://']:
            ico_url = f"{proto}{netloc}/favicon.ico"
            icon = try_get(ico_url)
            if icon:
                return icon

        # Step 2: 解析首頁 HTML 的 <link rel=icon ...>
        for proto in ['https://', 'http://']:
            html_url = f"{proto}{netloc}"
            html = try_get(html_url)
            if not html:
                continue
            html_str = html.decode('utf-8', errors='ignore')
            icon_links = re.findall(r'<link[^>]+rel=[\"\']?[^\"\'>]*icon[^\"\'>]*[\"\']?[^>]*>', html_str, re.I)
            for link in icon_links:
                href_match = re.search(r'href=[\"\']([^\"\']+)[\"\']', link, re.I)
                if href_match:
                    icon_href = href_match.group(1)
                    if icon_href.startswith('http'):
                        full_icon_url = icon_href
                    elif icon_href.startswith('//'):
                        full_icon_url = proto + icon_href.split('//', 1)[-1]
                    elif icon_href.startswith('/'):
                        full_icon_url = proto + netloc + icon_href
                    else:
                        full_icon_url = proto + netloc + '/' + icon_href
                    icon = try_get(full_icon_url)
                    if icon:
                        return icon
        return None
    except Exception as e:
        print(f"[favicon_handler] 從網址取得 favicon 失敗: {e}")
        return None

def get_favicon_bytes_from_file(path):
    """
    讀取本地 icon 檔案並回傳 bytes，失敗傳回 None
    """
    try:
        if not os.path.isfile(path):
            print(f"[favicon_handler] 檔案不存在: {path}")
            return None
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"[favicon_handler] 讀取本機 icon 失敗: {e}")
        return None

def extract_domain(url):
    """
    取得網址中的 domain 名稱（不含協定、路徑），供 log 分類
    """
    return re.sub(r'^https?://', '', url, flags=re.I).split('/')[0]
