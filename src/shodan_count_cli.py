"""
shodan_count_cli.py
支援 shodan count 的 CLI 與 HTTP API 雙模式自動切換。
"""

import subprocess
import requests

LIMIT = 100  # 預設最大限制（HTTP API 搜索時用不到，但維持一致）

def shodan_count_cli(query, timeout=15):
    """
    使用 shodan CLI 執行 count 查詢，失敗回傳 -1。
    """
    try:
        proc = subprocess.run(
            ['shodan', 'count', query],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            timeout=timeout
        )
        if proc.returncode != 0:
            print(f"[shodan_count_cli] CLI 執行錯誤: {proc.stderr.strip()}")
            return -1
        out = proc.stdout.strip()
        if out.isdigit():
            return int(out)
        if out == "0":
            return 0
        print(f"[shodan_count_cli] 無法解析 CLI 輸出: {out}")
        return -1
    except Exception as e:
        print(f"[shodan_count_cli] CLI 查詢例外: {e}")
        return -1

def shodan_count_api(query, api_key, timeout=15):
    """
    使用 HTTP API 執行 count 查詢，失敗回傳 -1。
    """
    url = "https://api.shodan.io/shodan/host/count"
    params = {
        'key': api_key,
        'query': query
    }
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        total = data.get('total')
        if total is not None:
            return total
        print(f"[shodan_count_api] API 回傳資料格式錯誤: {data}")
        return -1
    except Exception as e:
        print(f"[shodan_count_api] HTTP API 查詢錯誤: {e}")
        return -1

def shodan_count(query, api_key=None, use_http_api=False, timeout=15):
    """
    智能選擇 shodan count 查詢模式：
    - use_http_api=True 時直接用 HTTP API
    - 否則先嘗試 CLI，失敗再自動用 HTTP API
    """
    if use_http_api:
        if not api_key:
            print("[shodan_count] 缺少 API Key，無法使用 HTTP API")
            return -1
        return shodan_count_api(query, api_key, timeout=timeout)

    # 預設先用 CLI
    count = shodan_count_cli(query, timeout=timeout)
    if count < 0 and api_key:
        print("[shodan_count] CLI 失敗，改用 HTTP API")
        return shodan_count_api(query, api_key, timeout=timeout)
    return count

def batch_shodan_count(queries, api_key=None, use_http_api=False, timeout=15, verbose=False):
    """
    批次查詢，回傳 (query, count) 清單
    """
    results = []
    for q in queries:
        c = shodan_count(q, api_key=api_key, use_http_api=use_http_api, timeout=timeout)
        results.append((q, c))
        if verbose:
            print(f"[shodan_count] {q} -> {c}")
    return results

# 測試用
if __name__ == "__main__":
    test_queries = [
        'http.favicon.hash:-1642532492',
        'hostname:example.com',
        '"nginx" "PHP"'
    ]
    for q, c in batch_shodan_count(test_queries, verbose=True):
        print(f"{q:50} | {c}")
