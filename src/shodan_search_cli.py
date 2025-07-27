import requests
import json
import subprocess

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
    同時將結果寫入 log_path/shodan_result.log。
    batch 模式下不輸出結果。
    suspect_ips 是疑似目標 IP 集合，用於結果標示。
    """
    try:
        proc = subprocess.run(['shodan', 'search', query, '--limit', '100', '--json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=600)
        output = proc.stdout
        if proc.returncode != 0:
            print(f"[shodan CLI error]: {proc.stderr.strip()}")
            return []

        results = []
        # shodan CLI 輸出可能為多行 JSON，每行一筆結果
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                continue

        # 寫入完整結果到日誌
        if log_path:
            with open(os.path.join(log_path, "shodan_result.log"), "w", encoding="utf-8") as f:
                for entry in results:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        if not batch:
            print("\n=== Shodan 完整查詢結果 ===")
            for idx, item in enumerate(results, 1):
                print(f"[{idx:03d}] {format_shodan_result_entry(item, suspect_ips)}")

        return results

    except Exception as e:
        print(f"[shodan_search_cli] CLI 查詢錯誤: {e}")
        return []
