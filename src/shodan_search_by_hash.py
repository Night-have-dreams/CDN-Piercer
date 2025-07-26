import subprocess

FIELDS = ['ip_str', 'port', 'org', 'hostnames']
FIELD_STR = ','.join(FIELDS)
LIMIT = 100
SEPARATOR = "|"

def shodan_search_by_hash_cli(
        favhash, extra_query=None, log_path=None, batch=False, timeout=600, 
        suspect_ips=None, show_credits_fn=None):
    query = f"http.favicon.hash:{favhash}"
    if extra_query:
        query += f" {extra_query}"

    if show_credits_fn and not batch:
        credits = show_credits_fn()
        if credits is not None:
            print(f"[Shodan] Query credits: {credits}")

    print(f"\n[Shodan CLI 查詢語句]: shodan search --fields {FIELD_STR} --separator \"{SEPARATOR}\" --limit {LIMIT} \"{query}\"")

    try:
        proc = subprocess.Popen(
            ['shodan', 'search', '--fields', FIELD_STR, '--separator', SEPARATOR, '--limit', str(LIMIT), query],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8', errors='replace',   # 防止 Windows亂碼
            bufsize=1
        )
    except FileNotFoundError:
        print("[錯誤] shodan CLI 未安裝或無法執行！")
        return

    results = []
    try:
        print("\n=== Shodan 查詢結果 ===")
        idx = 1
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split(SEPARATOR, len(FIELDS)-1)
            while len(parts) < len(FIELDS): parts.append('')
            ip, port, org, hosts = parts
            mark = ""
            if suspect_ips and ip in suspect_ips:
                mark = '★疑似目標'
            print(f"【{idx:03d}】{(' ' + mark) if mark else ''}")
            print(f"  IP      : {ip}")
            print(f"  Port    : {port}")
            print(f"  Org     : {org}")
            print(f"  Host    : {hosts}")
            print("  --------------------------------------")
            results.append([ip, port, org, hosts, mark])
            idx += 1
        print(f"[Shodan] 共找到 {len(results)} 筆紀錄")
        if len(results) > 10:
            print("[提示] 結果筆數過多，建議加上關鍵字或端口縮小目標！")
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[Shodan CLI] 查詢超時（超過 {timeout} 秒），請嘗試減少查詢條件或稍後重試。")
        proc.terminate()
    except Exception as e:
        print(f"[錯誤] 讀取 Shodan CLI 輸出失敗: {e}")

    err = proc.stderr.read()
    if err:
        print(f"[Shodan CLI stderr]: {err.strip()}")

    if log_path and results:
        from src import log_manager
        log_manager.write_shodan_log(log_path, query, '\n'.join([SEPARATOR.join(map(str, r)) for r in results]))

    if not batch:
        if show_credits_fn:
            credits = show_credits_fn()
            if credits is not None:
                print(f"[Shodan] Query credits: {credits}")
        choice = input("是否修改查詢條件重查？(y/N): ").strip().lower()
        if choice == 'y':
            new_query = input("請輸入 Shodan 查詢條件 (e.g. port:80 title:TEST)：").strip()
            return shodan_search_by_hash_cli(favhash, new_query, log_path, batch, timeout, suspect_ips, show_credits_fn)
