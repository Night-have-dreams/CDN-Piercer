"""
combo_query_manager.py
根據 feature_extractor.py 的 {main, sub}，產生排列組合查詢語句清單
"""

from itertools import combinations, chain

def generate_combo_queries(features):
    queries = []

    favicon_hash = features.get("favicon_hash")
    hostname = features.get("hostname")
    cert_cn = features.get("cert_cn")
    title_variants = features.get("title_variants", [])
    tech_keywords = features.get("tech_keywords", [])

    # 單獨加入主關鍵字
    if favicon_hash:
        queries.append(f"http.favicon.hash:{favicon_hash}")
    if hostname:
        queries.append(f"hostname:{hostname}")
    if cert_cn:
        queries.append(f"ssl.cert.subject.CN:{cert_cn}")

    # title_variants 多個條件逐個加入
    queries.extend(title_variants)

    # 主關鍵字兩兩組合示範（可改成更複雜組合）
    main_keys = [q for q in queries if q.startswith(('http.favicon.hash', 'hostname', 'ssl.cert.subject.CN'))]
    for i in range(len(main_keys)):
        for j in range(i+1, len(main_keys)):
            queries.append(f"{main_keys[i]} {main_keys[j]}")

    # 主關鍵字 + title_variants 組合
    for main in main_keys:
        for title_q in title_variants:
            queries.append(f"{main} {title_q}")

    # 副關鍵字單獨加入
    for tech in tech_keywords:
        queries.append(f'"{tech}"')

    return list(set(queries))  # 去重
