#!/usr/bin/env python3
import argparse
import sys
import os
import datetime
import subprocess
import requests
import urllib.parse

from src import (
    site_crawler,
    feature_extractor,
    combo_query_manager,
    shodan_count_cli,
    shodan_search_cli,
    log_manager,
    dns_detector
)

def print_banner():
    print(r"""
   .----------------.  .----------------.  .-----------------.
  | .--------------. || .--------------. || .--------------. |
  | |     ______   | || |  ________    | || | ____  _____  | |
  | |   .' ___  |  | || | |_   ___ `.  | || ||_   \|_   _| | |
  | |  / .'   \_|  | || |   | |   `. \ | || |  |   \ | |   | |
======================= CDN Piercer v2.0 ======================➤
  | |  \ `.___.'\  | || |  _| |___.' / | || | _| |_\   |_  | |
  | |   `._____.'  | || | |________.'  | || ||_____|\____| | |
  | |              | || |              | || |              | |
  | '--------------' || '--------------' || '--------------' |
   '----------------'  '----------------'  '----------------' 
""")

def shodan_info_cli():
    try:
        proc = subprocess.run(['shodan', 'info'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=10)
        output = proc.stdout + proc.stderr
        if proc.returncode != 0:
            raise Exception(f"CLI error: {output.strip()}")
        for line in output.splitlines():
            if 'Query credits available' in line:
                credits = int(line.split(':')[-1].strip())
                return {'query_credits': credits}
        raise Exception("未找到 Query credits available")
    except Exception as e:
        print(f"[shodan CLI info error]: {e}")
        return None

def shodan_info_http(api_key):
    url = "https://api.shodan.io/api-info"
    params = {'key': api_key}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        return data
    except requests.exceptions.HTTPError as http_err:
        if r.status_code == 503:
            print("[警告] Shodan info 端點暫時無法使用（503 Service Unavailable），請稍後重試。")
            return None
        print(f"[錯誤] HTTP 錯誤: {http_err}")
        return None
    except Exception as e:
        print(f"[錯誤] 無法取得 Shodan info：{e}")
        return None

def check_api_key_with_count(api_key):
    try:
        count = shodan_count_cli.shodan_count_api("apache", api_key)
        if count >= 0:
            return True
    except Exception:
        pass
    return False

def get_api_key_and_mode(apikey_arg=None):
    cli_info = shodan_info_cli()
    if cli_info is not None:
        from pathlib import Path
        keyfile = Path.home() / ".shodan" / "api_key"
        if keyfile.exists():
            api_key = keyfile.read_text().strip()
        else:
            api_key = None
        return api_key, False

    key_to_test = apikey_arg or input("請輸入 Shodan API Key（HTTP API 模式）: ").strip()
    if check_api_key_with_count(key_to_test):
        return key_to_test, True

    print("[錯誤] API Key 無效或 Shodan 服務異常")
    return None, True

def parse_args():
    parser = argparse.ArgumentParser(description="CDNsearch v2.0")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', metavar='URL', help='分析網址')
    group.add_argument('-f', metavar='ICON_FILE', help='使用本機 icon')
    group.add_argument('-hash', metavar='HASH', help='直接使用 hash 查詢')
    parser.add_argument('-dns', metavar='DOMAIN_OR_off', help='DNS 查詢或 off 跳過')
    parser.add_argument('-report', action='store_true', help='歷史報告模式')
    parser.add_argument('--no-query', action='store_true', help='只計算 hash，不查 Shodan')
    parser.add_argument('-q', '--query', metavar='SHODAN_Q', help='額外 Shodan 查詢條件')
    parser.add_argument('-batch', action='store_true', help='批次模式，不互動')
    parser.add_argument('--apikey', metavar='API_KEY', help='直接使用 HTTP API Key（不使用 CLI）')
    return parser.parse_args()

def check_conflicts(args):
    exclusive = sum(bool(x) for x in (args.u, args.f, args.hash))
    if args.report and (exclusive or args.dns or args.query or args.no_query or args.batch):
        print("[ERROR] -report 只能單獨使用")
        sys.exit(1)
    if args.dns and args.dns.lower() != 'off' and (exclusive or args.query or args.no_query or args.batch):
        print("[ERROR] -dns domain 只能獨立使用")
        sys.exit(1)
    if exclusive > 1:
        print("[ERROR] -u, -f, -hash 只能擇一")
        sys.exit(1)
    if not (exclusive or args.dns or args.report):
        print("[ERROR] 必須指定 -u、-f、-hash 或 -dns 或 -report")
        sys.exit(1)

def select_best_query_interactively(valid_queries, args):
    count_ones = [q for q in valid_queries if q[1] == 1]
    if len(count_ones) > 1 and not args.batch:
        print("\n[提示] 有多筆 count=1 的查詢語句，請選擇其中一個：")
        for idx, (query, count) in enumerate(count_ones, 1):
            print(f"{idx}. {query} (count={count})")
        print(f"{len(count_ones)+1}. 自訂查詢語句")
        while True:
            choice = input(f"輸入選項（1-{len(count_ones)+1}）: ").strip()
            if choice.isdigit():
                choice = int(choice)
                if 1 <= choice <= len(count_ones):
                    return count_ones[choice - 1]
                elif choice == len(count_ones) + 1:
                    user_query = input("請輸入自訂查詢語句（留空取消）: ").strip()
                    if user_query:
                        return (user_query, -1)
                    else:
                        print("取消自訂查詢，請重新選擇。")
            print("輸入錯誤，請重新輸入。")
    else:
        return min(valid_queries, key=lambda x: (x[1], len(x[0])))

def format_shodan_result_entry(item, suspect_ips=None):
    ip = item.get('ip_str', item.get('ip', 'N/A')) or 'N/A'
    port = item.get('port', 'N/A') or 'N/A'
    org = item.get('org', 'N/A') or 'N/A'
    isp = item.get('isp', 'N/A') or 'N/A'
    hostnames = ", ".join(item.get('hostnames', [])) if item.get('hostnames') else 'N/A'
    location = item.get('location', {}) or {}
    city = location.get('city', 'N/A') or 'N/A'
    country = location.get('country_name', 'N/A') or 'N/A'
    mark = ''
    if suspect_ips and ip in suspect_ips:
        mark = '★疑似目標'

    return (f"IP: {ip:<15} Port: {str(port):<5} Org: {org:<20} ISP: {isp:<20} "
            f"City: {city:<15} Country: {country:<10} Hostnames: {hostnames} {mark}")


def main():
    print_banner()
    args = parse_args()
    check_conflicts(args)

    api_key, use_http_api = get_api_key_and_mode(apikey_arg=args.apikey)
    if api_key is None:
        print("[ERROR] 未提供有效 Shodan API Key，無法使用 Shodan 服務。")
        if args.dns and args.dns.lower() != 'off':
            domain = dns_detector.normalize_domain(args.dns)
            log_dir = log_manager.prepare_log_dir(domain=domain)
            dns_detector.print_dns_report(domain, log_to=log_dir)
        sys.exit(1)

    if args.report:
        print("[REPORT] 查詢報告模式，目前未實作")
        sys.exit(0)

    if args.dns and args.dns.lower() != 'off':
        domain = dns_detector.normalize_domain(args.dns)
        log_dir = log_manager.prepare_log_dir(domain=domain)
        dns_detector.print_dns_report(domain, log_to=log_dir)
        sys.exit(0)

    skip_dns = args.dns and args.dns.lower() == 'off'

    if args.u:
        url = args.u
        log_dir = None
        suspect_ips = set()

        print(f"[主流程] 分析網址: {url} (DNS查詢: {'否' if skip_dns else '是'})")

        if not skip_dns:
            domain = dns_detector.normalize_domain(url)
            log_dir = log_manager.prepare_log_dir(domain=domain)
            dns_detector.print_dns_report(domain, log_to=log_dir)
            all_records, all_ips, ip_cdn_map, cdn_provs = dns_detector.collect_dns_reports(domain)
            suspect_ips = {ip for ip, v in ip_cdn_map.items() if not v}
        else:
            domain = dns_detector.normalize_domain(url)
            log_dir = log_manager.prepare_log_dir(domain=domain)

        features = site_crawler.crawl_site_features(url)
        log_manager.write_features_log(log_dir, features)

        if features.get("favicon_hash") is None:
            print("[!] 自動取得 favicon 失敗！")
            while True:
                icon_path = input("請輸入本地 icon 檔案路徑，或直接 Enter 跳過: ").strip()
                if not icon_path:
                    print("[!] 跳過本地 icon，將用其他特徵繼續查詢。")
                    break
                if not os.path.isfile(icon_path):
                    print("[錯誤] 檔案不存在，請重新輸入。")
                    continue
                try:
                    import base64, mmh3
                    with open(icon_path, "rb") as f:
                        icon_bytes = f.read()
                    if icon_bytes:
                        b64 = base64.encodebytes(icon_bytes).decode('utf-8')
                        hashval = mmh3.hash(b64)
                        features["favicon_hash"] = hashval
                        log_manager.write_features_log(log_dir, features)
                        print(f"[Hash] 已補充本地 icon hash: {hashval}")
                        break
                    else:
                        print("[錯誤] 讀取 icon 檔案失敗。")
                except Exception as e:
                    print(f"[錯誤] 讀取 icon 檔失敗：{e}")
                    continue

        query_features = feature_extractor.extract_query_features(features)
        combo_queries = combo_query_manager.generate_combo_queries(query_features)

        query_count_list = []
        import time
        for q in combo_queries:
            if use_http_api:
                c = shodan_count_cli.shodan_count_api(q, api_key)
            else:
                c = shodan_count_cli.shodan_count(q)
            query_count_list.append((q, c))
            if not args.batch:
                print(f"[shodan_count] {q} → {c}")

        valid = [(q, c) for q, c in query_count_list if c and c > 0 and c != -1 and c <= 100]

        if not args.batch:
            print(f"\n[提示] 準備執行 Shodan 查詢，請確認是否繼續 (y/n):")
            yn = input().strip().lower()
            if yn != 'y':
                print("使用者取消查詢，程式結束。")
                sys.exit(0)

        best_query = None
        if valid:
            best_query = select_best_query_interactively(valid, args)
        else:
            if not args.batch:
                print("\n[!] 沒有命中的查詢語句，可考慮手動輸入 Shodan 查詢條件（或 Enter 跳過）:")
                user_query = input("請自訂查詢語句: ").strip()
                if user_query:
                    best_query = (user_query, -1)

        if best_query and not args.no_query:
            print(f"\n[Shodan Search] 執行查詢語句：{best_query[0]}")
            if use_http_api:
                from src.shodan_search_cli import shodan_search_api
                shodan_result = shodan_search_api(best_query[0], api_key)
            else:
                shodan_result = shodan_search_cli.shodan_search(
                    best_query[0], log_path=log_dir, batch=args.batch, suspect_ips=suspect_ips
                )
            log_manager.write_shodan_queries_log(log_dir, query_count_list)
            log_manager.write_shodan_result_log(log_dir, shodan_result)
            log_manager.write_summary_log(log_dir, {
                "target": url,
                "features": features,
                "best_query": best_query[0],
                "count": best_query[1],
                "shodan_result_count": len(shodan_result),
            })
            if shodan_result:
                print("\n=== Shodan 查詢結果 ===")
                for idx, item in enumerate(shodan_result, 1):
                    print(f"[{idx:03d}] {format_shodan_result_entry(item, suspect_ips)}")
            else:
                print("[!] Shodan 查詢無結果或查詢失敗。")
            print(f"\n[完成] 查詢與記錄已寫入：{log_dir}")
        else:
            print("[!] 未執行 Shodan 查詢。")

    elif args.f:
        icon_path = args.f
        import base64, mmh3
        try:
            with open(icon_path, "rb") as f:
                icon_bytes = f.read()
            if not icon_bytes:
                print("[錯誤] 讀取 icon 檔案失敗。")
                sys.exit(1)
            b64 = base64.encodebytes(icon_bytes).decode('utf-8')
            hashval = mmh3.hash(b64)
        except Exception as e:
            print(f"[錯誤] 讀取 icon 檔案失敗：{e}")
            sys.exit(1)

        log_dir = log_manager.prepare_log_dir(hashval='fromfile', timestamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        features = {
            "favicon_hash": hashval,
            "source": icon_path
        }
        log_manager.write_features_log(log_dir, features)
        if not args.no_query:
            query = f"http.favicon.hash:{hashval}"
            if args.query:
                query += f" {args.query}"
            if use_http_api:
                from src.shodan_search_cli import shodan_search_api
                shodan_result = shodan_search_api(query, api_key)
            else:
                shodan_result = shodan_search_cli.shodan_search(query)
            log_manager.write_shodan_result_log(log_dir, shodan_result)
            log_manager.write_summary_log(log_dir, {
                "icon_file": icon_path,
                "hash": hashval,
                "query": query,
                "shodan_result_count": len(shodan_result),
            })
            print(f"\n[完成] 查詢與記錄已寫入：{log_dir}")

    elif args.hash:
        hashval = args.hash
        log_dir = log_manager.prepare_log_dir(hashval=hashval, timestamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        features = {
            "favicon_hash": hashval,
            "source": "manual"
        }
        log_manager.write_features_log(log_dir, features)
        if not args.no_query:
            query = f"http.favicon.hash:{hashval}"
            if args.query:
                query += f" {args.query}"
            if use_http_api:
                from src.shodan_search_cli import shodan_search_api
                shodan_result = shodan_search_api(query, api_key)
            else:
                shodan_result = shodan_search_cli.shodan_search(query)
            log_manager.write_shodan_result_log(log_dir, shodan_result)
            log_manager.write_summary_log(log_dir, {
                "hash": hashval,
                "query": query,
                "shodan_result_count": len(shodan_result),
            })
            print(f"\n[完成] 查詢與記錄已寫入：{log_dir}")

    else:
        print("[ERROR] 必須指定 -u、-f 或 -hash")
        sys.exit(1)

if __name__ == "__main__":
    main()
