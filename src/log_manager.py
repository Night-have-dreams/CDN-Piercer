import os
import json
import datetime

def prepare_log_dir(domain=None, hashval=None, timestamp=None):
    """
    建立正確的 log 資料夾結構，回傳該次查詢專屬目錄。
    domain/hashval 為唯一分類，timestamp 必須全流程唯一（通常主程式啟動時決定）。
    """
    base = 'logs'
    timestamp = timestamp or datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    if domain:
        log_dir = os.path.join(base, 'domain', domain, timestamp)
    elif hashval:
        log_dir = os.path.join(base, 'hash', str(hashval), timestamp)
    else:
        log_dir = os.path.join(base, 'misc', timestamp)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def write_dns_log(log_dir, data):
    """
    輸出 DNS 查詢結果到 dns.log，可支援 dict/text。
    """
    path = os.path.join(log_dir, 'dns.log')
    with open(path, 'w', encoding='utf-8') as f:
        if isinstance(data, str):
            f.write(data)
        else:
            f.write(json.dumps(data, ensure_ascii=False, indent=2))

def write_favicon_file(log_dir, favicon_bytes):
    """
    存下取得的 favicon 二進位檔，命名為 favicon.ico。
    """
    path = os.path.join(log_dir, 'favicon.ico')
    with open(path, 'wb') as f:
        f.write(favicon_bytes)

def write_hash_log(log_dir, hashval):
    """
    將 hash 結果寫入 hash.log。
    """
    path = os.path.join(log_dir, 'hash.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(str(hashval))

def write_shodan_log(log_dir, query, result):
    """
    將 shodan 查詢記錄(含查詢字串與回應) append 進 shodan.log。
    """
    path = os.path.join(log_dir, 'shodan.log')
    with open(path, 'a', encoding='utf-8') as f:
        f.write(f'=== QUERY: {query}\n')
        f.write(result)
        f.write('\n\n')

def write_summary(log_dir, summary_obj):
    """
    儲存總結（如 json）。
    """
    path = os.path.join(log_dir, 'summary.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(summary_obj, f, ensure_ascii=False, indent=2)

def load_summary(log_dir):
    """
    讀取 summary.json。
    """
    path = os.path.join(log_dir, 'summary.json')
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
