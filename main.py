#!/usr/bin/env python3
import argparse
import sys
import os
import datetime
import subprocess

from src import favicon_handler, utils, dns_detector, log_manager
from src.shodan_search_by_hash import shodan_search_by_hash_cli

def print_banner():
    print("\n=== CDNsearch v1.0 ===\n")

def shodan_info():
    proc = subprocess.run(['shodan', 'info'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
    out = proc.stdout + proc.stderr
    if 'Query credits available' in out:
        for line in out.splitlines():
            if 'Query credits available' in line:
                try:
                    return {'query_credits': int(line.split(':')[-1].strip()), 'raw': out}
                except:
                    continue
    if 'Please run "shodan init' in out:
        return 'NO_API_KEY'
    if 'Invalid API key' in out:
        return 'INVALID_API_KEY'
    return 'UNKNOWN'

def shodan_init(api_key):
    proc = subprocess.run(['shodan', 'init', api_key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
    out = proc.stdout + proc.stderr
    return 'API key saved' in out

def get_valid_api_key_and_credits():
    while True:
        info = shodan_info()
        if isinstance(info, dict):
            from pathlib import Path
            keyfile = Path.home() / ".shodan" / "api_key"
            api_key = keyfile.read_text().strip() if keyfile.exists() else None
            return api_key, info['query_credits']
        if info == 'NO_API_KEY':
            print("[!] 尚未設定 Shodan API KEY")
            key = input("請輸入 Shodan API KEY: ").strip()
            if not shodan_init(key):
                print("[錯誤] API KEY 設定失敗，請重新輸入。")
                continue
        elif info == 'INVALID_API_KEY':
            print("[錯誤] API KEY 無效，請重新輸入。")
            key = input("請輸入 Shodan API KEY: ").strip()
            if not shodan_init(key):
                print("[錯誤] API KEY 設定失敗，請重新輸入。")
                continue
        else:
            print("[錯誤] 無法判斷 shodan info 回應，請檢查 CLI 環境")
            sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="CDNsearch v1.0")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', metavar='URL', help='目標網址或域名')
    group.add_argument('-f', metavar='ICON_FILE', help='使用本機 icon 檔案')
    group.add_argument('-hash', metavar='HASH', help='直接使用 hash 查詢')
    parser.add_argument('-dns', metavar='DOMAIN_OR_off', help='DNS 查詢或使用 -dns off 跳過 DNS 查詢')
    parser.add_argument('--no-query', action='store_true', help='只計算 hash，不查 Shodan')
    parser.add_argument('-q','--query', metavar='SHODAN_Q', help='額外 Shodan 查詢條件，例如 -q \'port:80 title:test\'')
    parser.add_argument('-report', action='store_true', help='歷史報告模式(未實裝)')
    parser.add_argument('-batch', action='store_true', help='批次模式，不互動')
    return parser.parse_args()

def check_conflicts(args):
    exclusive = sum(bool(x) for x in (args.u, args.f, args.hash))
    if args.report and (exclusive or args.dns or args.query or args.no_query or args.batch):
        print("[ERROR] -report 只能單獨使用"); sys.exit(1)
    if args.dns and args.dns.lower() != 'off' and (exclusive or args.query or args.no_query or args.batch):
        print("[ERROR] -dns domain 只能獨立使用"); sys.exit(1)
    if exclusive > 1:
        print("[ERROR] -u, -f, -hash 只能擇一"); sys.exit(1)
    if not (exclusive or args.dns or args.report):
        print("[ERROR] 必須指定 -u、-f、-hash 或 -dns 或 -report"); sys.exit(1)

def main():
    START_TIME = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    print_banner()
    args = parse_args(); check_conflicts(args)
    api_key, credits = get_valid_api_key_and_credits()

    def show_credits():
        info = shodan_info()
        return info['query_credits'] if isinstance(info, dict) else None

    if args.report:
        print("[REPORT] 查詢報告模式 (尚未實裝)"); # info_report.show_report()TODO
        sys.exit(0)

    if args.dns and args.dns.lower() != 'off':
        dom = dns_detector.normalize_domain(args.dns)
        log_dir = log_manager.prepare_log_dir(domain=dom, timestamp=START_TIME)
        dns_detector.print_dns_report(dom, log_to=log_dir)
        sys.exit(0)

    skip_dns = (args.dns and args.dns.lower() == 'off')
    log_dir = None
    suspect_ips = set()

    if args.u:
        print(f"[主流程] 分析網址: {args.u} (DNS執行: {'否' if skip_dns else '是'})")
        dom = favicon_handler.extract_domain(args.u) if hasattr(favicon_handler, "extract_domain") else dns_detector.normalize_domain(args.u)
        log_dir = log_manager.prepare_log_dir(domain=dom, timestamp=START_TIME)

        # DNS 查詢與結論
        if not skip_dns:
            print("[主流程] 執行 DNS 查詢...")
            dns_detector.print_dns_report(dom, log_to=log_dir)  # <=== 這行保證完整報告
            all_records, all_ips, ip_cdn_map, cdn_provs = dns_detector.collect_dns_reports(dom)
            suspect_ips = {ip for ip, v in ip_cdn_map.items() if not v}

        icon_bytes = favicon_handler.get_favicon_bytes_from_url(args.u, verify=False)
        if icon_bytes:
            log_manager.write_favicon_file(log_dir, icon_bytes)
            h = utils.calc_favicon_hash(icon_bytes)
            log_manager.write_hash_log(log_dir, h)
            print(f"[Hash] {h}")
            if not args.no_query:
                shodan_search_by_hash_cli(
                    h, args.query, log_dir, batch=args.batch,
                    suspect_ips=suspect_ips, show_credits_fn=show_credits
                )
        else:
            print("[主流程] 自動取得 favicon 失敗！請手動指定 icon 檔案。")
            while True:
                path = input("輸入 icon 檔案路徑 或 Enter 放棄: ").strip()
                if not path:
                    print("跳過查詢"); break
                icon_bytes = favicon_handler.get_favicon_bytes_from_file(path)
                if icon_bytes:
                    log_manager.write_favicon_file(log_dir, icon_bytes)
                    h = utils.calc_favicon_hash(icon_bytes)
                    log_manager.write_hash_log(log_dir, h)
                    print(f"[Hash] {h}")
                    if not args.no_query:
                        shodan_search_by_hash_cli(
                            h, args.query, log_dir, batch=args.batch,
                            suspect_ips=suspect_ips, show_credits_fn=show_credits
                        )
                    break
                print("讀取失敗，請重試或 Enter 放棄")

    elif args.f:
        print(f"[主流程] 使用本機 icon 檔案: {args.f}")
        log_dir = log_manager.prepare_log_dir(hashval='fromfile', timestamp=START_TIME)
        icon_bytes = favicon_handler.get_favicon_bytes_from_file(args.f)
        if icon_bytes:
            log_manager.write_favicon_file(log_dir, icon_bytes)
            h = utils.calc_favicon_hash(icon_bytes)
            log_manager.write_hash_log(log_dir, h)
            print(f"[Hash] {h}")
            if not args.no_query:
                shodan_search_by_hash_cli(
                    h, args.query, log_dir, batch=args.batch,
                    show_credits_fn=show_credits
                )
        else:
            print("[主流程] 讀取 icon 失敗，跳過查詢")
    elif args.hash:
        print(f"[主流程] 使用指定 hash: {args.hash}")
        log_dir = log_manager.prepare_log_dir(hashval=args.hash, timestamp=START_TIME)
        log_manager.write_hash_log(log_dir, args.hash)
        if not args.no_query:
            shodan_search_by_hash_cli(
                args.hash, args.query, log_dir, batch=args.batch,
                show_credits_fn=show_credits
            )

    print(f"[完成] {START_TIME} 流程結束。")

if __name__ == "__main__":
    main()
