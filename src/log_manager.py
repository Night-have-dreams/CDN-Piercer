import os
import json
import datetime

def prepare_log_dir(domain=None, hashval=None, timestamp=None):
    """
    建立日誌資料夾，結構如 logs/domain/YYYYmmdd_HHMMSS/
    或 logs/hashval/YYYYmmdd_HHMMSS/
    """
    base_dir = os.path.join(os.getcwd(), "logs")
    if not timestamp:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if domain:
        log_dir = os.path.join(base_dir, domain, timestamp)
    elif hashval:
        log_dir = os.path.join(base_dir, str(hashval), timestamp)
    else:
        log_dir = os.path.join(base_dir, "unknown", timestamp)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def write_features_log(log_dir, features_dict):
    """
    將爬蟲抓取的特徵 dict 寫入 features.json。
    """
    path = os.path.join(log_dir, "features.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(features_dict, f, ensure_ascii=False, indent=2)

def write_shodan_queries_log(log_dir, queries_with_counts):
    """
    將所有查詢語句及其 count 寫入 shodan_queries.log，格式：<query>\t<count>
    """
    path = os.path.join(log_dir, "shodan_queries.log")
    with open(path, "w", encoding="utf-8") as f:
        for query, count in queries_with_counts:
            f.write(f"{query}\t{count}\n")

def write_shodan_result_log(log_dir, result_list):
    """
    將 Shodan 查詢結果寫入 shodan_result.log，逐條寫入 JSON 字串或自訂格式。
    """
    path = os.path.join(log_dir, "shodan_result.log")
    with open(path, "w", encoding="utf-8") as f:
        for entry in result_list:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def write_summary_log(log_dir, summary_obj):
    """
    將總結資訊寫入 summary.json，包含目標、用到的查詢、結果統計等。
    """
    path = os.path.join(log_dir, "summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary_obj, f, ensure_ascii=False, indent=2)

def load_summary(log_dir):
    """
    讀取 summary.json，回傳 dict 或 None。
    """
    path = os.path.join(log_dir, "summary.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_dns_log(log_dir, dns_data):
    """
    將 DNS 查詢資料寫入 dns.log，格式可自訂（此示範為 JSON）。
    """
    path = os.path.join(log_dir, "dns.log")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(dns_data, f, ensure_ascii=False, indent=2)

def write_favicon_file(log_dir, favicon_bytes):
    """
    將 favicon.ico bytes 寫入檔案。
    """
    path = os.path.join(log_dir, "favicon.ico")
    with open(path, "wb") as f:
        f.write(favicon_bytes)

def write_hash_log(log_dir, hashval):
    """
    將 hash 值寫入 hash.log，方便快速檢視。
    """
    path = os.path.join(log_dir, "hash.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(hashval) + "\n")

def write_shodan_log(log_dir, query, result):
    """
    將單次 Shodan 查詢語句與結果寫入 shodan.log，方便追蹤。
    """
    path = os.path.join(log_dir, "shodan.log")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"Query: {query}\n")
        for entry in result:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.write("\n---\n")

# 你也可以根據需要加入讀取功能、日誌輪替等
