#!/usr/bin/env python3
import argparse
import sys
import os
import datetime
import subprocess
import textwrap

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

def get_api_key_and_mode(apikey_arg=None):
    """
    決定使用 CLI 模式或 HTTP API 模式
    1. 先測試 shodan info 是否可用
    2. 若 CLI 模式不可用 → 請使用者輸入 API key 並用 count 測試
    """
    def shodan_info_cli():
        try:
            proc = subprocess.run(['shodan', 'info'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=10)
            if proc.returncode != 0:
                return None
            for line in proc.stdout.splitlines():
                if 'Query credits available' in line:
                    credits = int(line.split(':')[-1].strip())
                    return {'query_credits': credits}
        except Exception:
            return None
        return None

    cli_info = shodan_info_cli()
    if cli_info and cli_info.get("query_credits", 0) >= 0:
        print(f"[INFO] Shodan CLI 可用，剩餘 Query credits: {cli_info['query_credits']}")
        return None, False  # CLI 模式

    api_key = apikey_arg or input("請輸入 Shodan API Key（HTTP API 模式）: ").strip()
    if not api_key:
        print("[錯誤] 未輸入 API Key，無法使用 Shodan")
        return None, True

    print("[INFO] 測試輸入的 API Key 是否有效 ...")
    if shodan_count_cli.shodan_count_api("apache", api_key) >= 0:
        print("[INFO] API Key 驗證成功，使用 HTTP API 模式")
        return api_key, True

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

def format_shodan_result_entry(item, suspect_ips=None, width=80):
    ip = item.get('ip_str', item.get('ip', 'N/A')) or 'N/A'
    port = item.get('port', 'N/A') or 'N/A'
    org = item.get('org', 'N/A') or 'N/A'
    isp = item.get('isp', 'N/A') or 'N/A'
    location = item.get('location', {}) or {}
    city = location.get('city', 'N/A') or 'N/A'
    country = location.get('country_name', 'N/A') or 'N/A'
    mark = ''
    if suspect_ips and ip in suspect_ips:
        mark = '★疑似目標'

    raw_hostnames = item.get('hostnames', []) or []
    hostnames_str = ", ".join(raw_hostnames)

    # 嘗試分離 Hostnames 與 HTTP Headers (若有)
    if '\\r\\n' in hostnames_str or '\r\n' in hostnames_str:
        parts = hostnames_str.split('\\r\\n')
        hostname_part = parts[0]
        header_part = "\\r\\n".join(parts[1:])
    else:
        hostname_part = hostnames_str
        header_part = None

    lines = []
    lines.append(f"IP      : {ip} {mark}")
    lines.append(f"Port    : {port}")
    lines.append(f"Org     : {org}")
    lines.append(f"ISP     : {isp}")
    lines.append(f"City    : {city}")
    lines.append(f"Country : {country}")
    lines.append("Hostnames:")
    lines.extend(textwrap.wrap(hostname_part, width=width, initial_indent='  ', subsequent_indent='  '))
    if header_part:
        lines.append("HTTP Headers:")
        lines.extend(textwrap.wrap(header_part, width=width, initial_indent='  ', subsequent_indent='  '))

    return "\n".join(lines)


def interactive_count_and_query(base_query, api_key, use_http_api, max_limit=10, batch=False):
    query = base_query
    while True:
        if use_http_api:
            count = shodan_count_cli.shodan_count_api(query, api_key)
        else:
            count = shodan_count_cli.shodan_count(query)

        if not batch:
            print(f"[shodan_count] {query} -> {count}")

        if count == -1:
            print("[錯誤] 查詢失敗，請檢查網路連線或 API key")
            return []
        elif count == 0:
            print("[結果] 無匹配結果，請確認查詢條件。")
            if batch or input("是否要重新輸入關鍵字加強鎖定？(y/n): ").lower() != 'y':
                return []
        elif count > max_limit:
            print(f"[結果] 匹配結果過多 ({count} 筆)，建議加入關鍵字縮小範圍。")
            if batch or input("是否要加入關鍵字？(y/n): ").lower() != 'y':
                break
        else:
            break

        keyword = input("請輸入關鍵字（留空取消）：").strip()
        if not keyword:
            print("取消新增關鍵字，使用原始查詢。")
            break
        query += f" {keyword}"

    if use_http_api:
        from src.shodan_search_cli import shodan_search_api
        return shodan_search_api(query, api_key)
    else:
        from src.shodan_search_cli import shodan_search_cli
        return shodan_search_cli(query)

def main():
    print_banner()
    args = parse_args()
    check_conflicts(args)

    api_key, use_http_api = get_api_key_and_mode(apikey_arg=args.apikey)

    if use_http_api and not api_key:
        print("[ERROR] 未提供有效 Shodan API Key，無法使用 Shodan 服務。")
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
                    with open(icon_path, "rb") as f:
                        icon_bytes = f.read()
                    import base64, mmh3
                    if icon_bytes:
                        b64 = base64.encodebytes(icon_bytes).decode('utf-8')
                        hashval = mmh3.hash(b64)
                        features["favicon_hash"] = hashval
                        log_manager.write_features_log(log_dir, features)
                        print(f"[Hash] 已補充本地 icon hash: {hashval}")
                        break
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
                from src.shodan_search_cli import shodan_search_cli
                shodan_result = shodan_search_cli(
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
                    print(f"[{idx:03d}]\n{format_shodan_result_entry(item, suspect_ips)}\n")
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
        except Exception as e:
            print(f"[錯誤] 讀取 icon 檔案失敗：{e}")
            sys.exit(1)
        b64 = base64.encodebytes(icon_bytes).decode('utf-8')
        hashval = mmh3.hash(b64)
        print(f"[DEBUG] hash 值:{hashval}")

        log_dir = log_manager.prepare_log_dir(hashval='fromfile', timestamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        features = {
            "favicon_hash": hashval,
            "source": icon_path
        }
        log_manager.write_features_log(log_dir, features)

        if not args.no_query:
            base_query = f"http.favicon.hash:{hashval}"
            if args.query:
                base_query += f" {args.query}"
            shodan_result = interactive_count_and_query(base_query, api_key, use_http_api, batch=args.batch)
            log_manager.write_shodan_result_log(log_dir, shodan_result)
            log_manager.write_summary_log(log_dir, {
                "icon_file": icon_path,
                "hash": hashval,
                "query": base_query,
                "shodan_result_count": len(shodan_result),
            })
            if shodan_result:
                print("\n=== Shodan 查詢結果 ===")
                for idx, item in enumerate(shodan_result, 1):
                    print(f"[{idx:03d}]\n{format_shodan_result_entry(item)}\n")
            else:
                print("[!] Shodan 查詢無結果或查詢失敗。")
            print(f"\n[完成] 查詢與記錄已寫入：{log_dir}")

    elif args.hash:
        hashval = args.hash
        print(f"[DEBUG] hash 值:{hashval}")
        log_dir = log_manager.prepare_log_dir(hashval=hashval, timestamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        features = {
            "favicon_hash": hashval,
            "source": "manual"
        }
        log_manager.write_features_log(log_dir, features)

        if not args.no_query:
            base_query = f"http.favicon.hash:{hashval}"
            if args.query:
                base_query += f" {args.query}"
            shodan_result = interactive_count_and_query(base_query, api_key, use_http_api, batch=args.batch)
            log_manager.write_shodan_result_log(log_dir, shodan_result)
            log_manager.write_summary_log(log_dir, {
                "hash": hashval,
                "query": base_query,
                "shodan_result_count": len(shodan_result),
            })
            if shodan_result:
                print("\n=== Shodan 查詢結果 ===")
                for idx, item in enumerate(shodan_result, 1):
                    print(f"[{idx:03d}]\n{format_shodan_result_entry(item)}\n")
            else:
                print("[!] Shodan 查詢無結果或查詢失敗。")
            print(f"\n[完成] 查詢與記錄已寫入：{log_dir}")

    else:
        print("[ERROR] 必須指定 -u、-f 或 -hash")
        sys.exit(1)


if __name__ == "__main__":
    main()
