import requests
import json
import subprocess
import os
import re

def shodan_search_api(query, api_key, limit=100, timeout=60):
    """
    使用 Shodan HTTP API 進行搜尋，回傳完整匹配結果列表。
    """
    url = "https://api.shodan.io/shodan/host/search"
    params = {
        'key': api_key,
        'query': query,
        'limit': limit
    }
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            print(f"[錯誤] API回傳非 dict: {data}")
            return []
        return data.get('matches', [])
    except Exception as e:
        print(f"[shodan_search_api] HTTP API 查詢錯誤: {e}")
        return []

def format_shodan_result_entry(item, suspect_ips=None):
    ip = item.get('ip_str', item.get('ip', 'N/A'))
    port = item.get('port', 'N/A')
    org = item.get('org', 'N/A')
    isp = item.get('isp', 'N/A')
    hostnames = ", ".join(item.get('hostnames', [])) if item.get('hostnames') else 'N/A'
    location = item.get('location', {})
    city = location.get('city', 'N/A')
    country = location.get('country_name', 'N/A')
    mark = ''
    if suspect_ips and ip in suspect_ips:
        mark = '★疑似目標'

    return (f"IP: {ip:<15} Port: {str(port):<5} Org: {org:<20} ISP: {isp:<20} "
            f"City: {city:<15} Country: {country:<10} Hostnames: {hostnames} {mark}")

def shodan_search_cli(query, log_path=None, batch=False, suspect_ips=None):
    """
    使用 Shodan CLI 進行搜尋，回傳完整匹配結果列表。
    解析 CLI 文字表格輸出，轉成 dict 列表。
    同時將結果寫入 log_path/shodan_result.log。
    batch 模式下不輸出結果。
    suspect_ips 是疑似目標 IP 集合，用於結果標示。
    """
    try:
        proc = subprocess.run(
            ['shodan', 'search', query, '--limit', '100'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            timeout=600
        )

        print(f"[DEBUG shodan CLI stdout]:\n{proc.stdout}")
        print(f"[DEBUG shodan CLI stderr]:\n{proc.stderr}")

        if proc.returncode != 0:
            print(f"[shodan CLI error]: {proc.stderr.strip()}")
            return []

        results = []

        # 解析文字輸出表格，範例格式（第一行是表頭）：
        # IP             Port  Hostnames                     ...
        # 35.72.212.8    443   ec2-35-72-212-8.ap-northeast-1.compute.amazonaws.com;www.omia.com.tw;new.omia.com.tw ...
        # 依空白切割前三欄（IP, Port, Hostnames），hostnames用分號分割
        lines = proc.stdout.splitlines()
        # 跳過表頭、空行及分隔線行
        # 簡單判斷第一行是否為表頭（包含IP Port Hostnames）
        if len(lines) > 0 and ('IP' in lines[0] and 'Port' in lines[0] and 'Hostnames' in lines[0]):
            data_lines = lines[1:]
        else:
            data_lines = lines

        for line in data_lines:
            if not line.strip():
                continue
            # 匹配開頭 IP 位址
            m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+([^\s].*)$', line)
            if m:
                ip = m.group(1)
                port = int(m.group(2))
                hostnames_str = m.group(3).strip()
                hostnames = hostnames_str.split(';') if hostnames_str else []
                results.append({
                    'ip_str': ip,
                    'port': port,
                    'hostnames': hostnames,
                    # 其他欄位缺省
                })

        # 寫入完整結果到日誌
        if log_path:
            with open(os.path.join(log_path, "shodan_result.log"), "w", encoding="utf-8") as f:
                for entry in results:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        #if not batch:
            #print("\n=== Shodan 完整查詢結果 ===")
            #for idx, item in enumerate(results, 1):
             #   print(f"[{idx:03d}] {format_shodan_result_entry(item, suspect_ips)}")

        return results

    except Exception as e:
        print(f"[shodan_search_cli] CLI 查詢錯誤: {e}")
        return []
