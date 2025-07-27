import re

def safe_set_feature(features, key, value):
    """
    只在 value 有效（非 None、非空字串）時寫入 features 字典。
    """
    if value and (not isinstance(value, str) or value.strip() != ''):
        features[key] = value

def extract_title_variants(title, max_keywords=5):
    """
    對 title 字串產生多種查詢變體，包括：
    - 原始完整 title (帶雙引號)
    - 前 max_keywords 個詞組合 (帶雙引號)
    - 後 max_keywords 個詞組合 (帶雙引號)
    - 拆分後的單字列表（無引號）
    返回字串列表，適用於 Shodan 查詢語句組合。
    """
    if not title or not isinstance(title, str):
        return []

    title = title.strip()
    variants = []

    # 1. 完整原文帶雙引號
    variants.append(f'title:"{title}"')

    # 2. 拆分字串（逗號、空白、常見分隔符）
    split_words = re.split(r'[\s,，\-_\|\/]+', title)
    split_words = [w for w in split_words if len(w) > 1]

    # 3. 前 max_keywords 個詞
    if len(split_words) >= max_keywords:
        front = ' '.join(split_words[:max_keywords])
        variants.append(f'title:"{front}"')

    # 4. 後 max_keywords 個詞
    if len(split_words) >= max_keywords:
        tail = ' '.join(split_words[-max_keywords:])
        variants.append(f'title:"{tail}"')

    # 5. 單字分別加入（無雙引號，提升模糊匹配）
    variants.extend([f'title:{word}' for word in split_words])

    # 去重
    return list(dict.fromkeys(variants))

def extract_query_features(features_raw):
    """
    將爬蟲原始特徵字典轉換為Shodan查詢特徵，
    包含主關鍵字與副關鍵字分別輸出。
    """
    features = {}

    # 安全設定 favicon hash
    safe_set_feature(features, "favicon_hash", features_raw.get("favicon_hash"))

    # 安全設定 hostname
    safe_set_feature(features, "hostname", features_raw.get("hostname"))

    # 安全設定 cert_cn
    safe_set_feature(features, "cert_cn", features_raw.get("cert_cn"))

    # 處理 title，產生多版本查詢字串
    title_raw = features_raw.get("title")
    title_variants = extract_title_variants(title_raw, max_keywords=3)
    safe_set_feature(features, "title_variants", title_variants)

    # 副關鍵字（header技術特徵），過濾空值
    tech_keywords = features_raw.get("tech_keywords", [])
    tech_keywords = [k.strip() for k in tech_keywords if k and k.strip()]
    if tech_keywords:
        features["tech_keywords"] = tech_keywords

    return features
