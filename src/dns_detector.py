import dns.resolver
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# CDN特徵字串
CDN_PROVIDERS = {
    'cloudflare': ['cloudflare', '.cdn.cloudflare.net'],
    'akamai': ['akamai', 'akadns', 'akamaiedge'],
    'fastly': ['fastly', 'fastly.net'],
    'incapsula': ['incapdns.net', 'incapsula'],
    'azure': ['azure', 'trafficmanager'],
    'aws': ['awsdns', 'cloudfront'],
    'aliyun': ['aliyun', 'alibaba'],
    'wangsu': ['wangsu', 'wscdns'],
    'bunnycdn': ['bunnycdn'],
}

# 擴充的全球及區域性公開 DNS 伺服器
GLOBAL_DNS_SERVERS = [
    # 全球主要 DNS
    ('Cloudflare', '1.1.1.1'),
    ('Cloudflare', '1.0.0.1'),
    ('Cloudflare IPv6', '2606:4700:4700::1111'),
    ('Cloudflare IPv6', '2606:4700:4700::1001'),
    ('Google', '8.8.8.8'),
    ('Google', '8.8.4.4'),
    ('Google IPv6', '2001:4860:4860::8888'),
    ('Google IPv6', '2001:4860:4860::8844'),
    ('Quad9', '9.9.9.9'),
    ('Quad9', '149.112.112.112'),
    ('Quad9 IPv6', '2620:fe::fe'),
    ('Quad9 IPv6', '2620:fe::9'),
    ('OpenDNS', '208.67.222.222'),
    ('OpenDNS', '208.67.220.220'),
    ('OpenDNS IPv6', '2620:119:35::35'),
    ('OpenDNS IPv6', '2620:119:53::53'),
    ('Control D', '76.76.2.0'),
    ('Control D alt', '76.76.10.0'),
    ('AdGuard', '94.140.14.14'),
    ('AdGuard', '94.140.15.15'),
    ('CleanBrowsing', '185.228.168.9'),
    ('CleanBrowsing', '185.228.169.9'),
    ('Comodo Secure DNS', '8.26.56.26'),
    ('Comodo Secure DNS 2', '8.20.247.20'),
    ('Alternate DNS', '76.76.19.19'),
    ('Alternate DNS alt', '76.223.122.150'),
    # 歐洲
    ('DNS4EU', '86.54.11.1'),
    ('DNS4EU alt', '86.54.11.201'),
    ('DNS4EU child', '86.54.11.12'),
    ('G‑Core', '95.85.95.85'),
    ('G‑Core IPv6', '2a03:90c0:999d::1'),
    ('Yandex', '77.88.8.8'),
    ('Yandex IPv6', '2a02:6b8::feed:0ff'),
    # 中國
    ('百度 BaiduDNS', '180.76.76.76'),
    ('阿里 AliDNS', '223.5.5.5'),
    ('阿里 AliDNS', '223.6.6.6'),
    ('114DNS', '114.114.114.114'),
    ('114DNS', '114.114.115.115'),
    # 台灣
    ('Hinet', '168.95.1.1'),
    ('Hinet', '168.95.192.1'),
    ('So-net', '61.31.233.1'),
    ('SeedNet', '139.175.55.244'),
    ('Taiwan Fixed', '168.95.98.254'),
    # 香港
    ('HKBN', '203.80.96.10'),
    ('HKBN', '203.80.96.9'),
    # 日本
    ('NTT', '129.250.35.250'),
    ('NTT', '129.250.35.251'),
    ('ODN', '143.90.130.208'),
    ('ODN', '143.90.130.209'),
    # 韓國
    ('KT', '168.126.63.1'),
    ('KT', '168.126.63.2'),
    ('SK Broadband', '210.220.163.82'),
    ('SK Broadband', '219.250.36.130'),
    # 新加坡
    ('Singtel', '165.21.83.88'),
    ('Singtel', '165.21.100.88'),
    # 俄羅斯
    ('Yandex', '77.88.8.1'),
    # V2EX
    ('V2EX DNS', '199.91.73.222'),
    ('V2EX DNS', '178.79.131.110'),
    # 美國主流 ISP
    ('Verizon', '4.2.2.1'),
    ('Verizon', '4.2.2.2'),
    ('AT&T', '68.94.156.1'),
    ('AT&T', '68.94.157.1'),
    ('Comcast', '75.75.75.75'),
    ('Comcast', '75.75.76.76'),
    ('Sprint', '204.117.214.10'),
    ('Sprint', '199.2.252.10'),
    # 加拿大
    ('Rogers', '64.71.255.204'),
    ('Rogers', '64.71.255.198'),
    ('Bell', '207.164.234.129'),
    ('Bell', '207.164.234.193'),
    # 歐洲各國
    ('Deutsche Telekom', '194.25.2.129'),
    ('Orange FR', '80.10.246.2'),
    ('BT UK', '213.120.234.42'),
    ('Vodafone IT', '83.224.65.65'),
    ('Telefonica ES', '80.58.61.250'),
    ('Türk Telekom', '195.175.39.39'),
    ('O2 Czech', '160.218.10.200'),
    ('Swisscom CH', '195.186.4.111'),
    ('Telenor NO', '148.122.161.1'),
    # 澳洲
    ('Telstra', '139.130.4.4'),
    ('Optus', '198.142.0.51'),
    # 印度
    ('Airtel', '202.56.230.5'),
    ('BSNL', '218.248.255.146'),
    ('Reliance Jio', '49.44.59.37'),
    ('Tata Communications', '203.197.12.30'),
    # 南美洲
    ('Claro BR', '189.4.128.12'),
    ('Oi BR', '200.222.0.34'),
    ('Telecom Argentina', '200.45.191.35'),
    ('Entel Chile', '164.77.222.10'),
    # 非洲
    ('MTN NG', '172.18.254.2'),        # 奈及利亞
    ('Telkom ZA', '196.25.1.1'),      # 南非
    ('Safaricom KE', '196.201.208.225'), # 肯亞
    # 中東
    ('STC SA', '86.111.192.51'),        # 沙烏地阿拉伯
    ('Etisalat UAE', '86.96.1.2'),      # 阿聯酋
    ('Bezeq IL', '192.115.106.70'),     # 以色列
    # 更多可根據需求再擴充...
]

# Cloudflare 已知常見 IP 範圍（CIDR）
CLOUDFLARE_CIDR = [
    '104.16.0.0/12',
    '172.64.0.0/13',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '162.158.0.0/15',
    '198.41.128.0/17',
    '188.114.96.0/23', 
]

def normalize_domain(domain):
    """
    移除 http(s):// 與路徑部分，只保留 domain，例如 https://www.xxx.com/path 轉 www.xxx.com
    """
    return re.sub(r'^https?://', '', domain, flags=re.I).split('/')[0]

def is_ip_in_cidr(ip, cidr_list):
    """
    判斷 IP 是否在某個 CIDR 範圍內
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c) for c in cidr_list)
    except Exception:
        return False

def is_ip_cdn(ip):
    """
    判斷 IP 是否為 Cloudflare（或未來其他CDN）IP，回傳 CDN 名稱或 None
    """
    if is_ip_in_cidr(ip, CLOUDFLARE_CIDR):
        return 'cloudflare'
    # 可以加: if is_ip_in_cidr(ip, FASTLY_CIDR): return 'fastly'
    return None

def analyze_cdn(records):
    """
    判斷 DNS 查詢結果中有無 CDN 字串特徵，回傳供應商清單
    """
    cdns = set()
    vals = records.get('CNAME',[]) + records.get('A',[]) + records.get('NS',[])
    for v in vals:
        lv = str(v).lower()
        for p, keys in CDN_PROVIDERS.items():
            if any(k in lv for k in keys):
                cdns.add(p)
    return list(cdns)

def query_dns(domain, nameserver, timeout=5):
    """
    用單一 DNS 伺服器查詢 domain 的 A, AAAA, CNAME, NS 記錄，回傳 dict
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = timeout
    result = {}
    for q in ['A','AAAA','CNAME','NS']:
        try:
            result[q] = [r.to_text() for r in resolver.resolve(domain, q)]
        except Exception:
            result[q] = []
    return result

def collect_dns_reports(domain, max_workers=16, timeout=5):
    """
    使用多線程同時查詢所有公開 DNS，整合回傳：
    - all_records: 每個 nameserver 的完整回應
    - all_ips: 全部出現過的A記錄IP set
    - ip_cdn_map: 各IP是否屬於CDN
    - cdn_provs: 檢測到的CDN廠商
    """
    all_records = {}
    all_ips = set()
    ip_cdn_map = {}
    cdn_provs = set()

    def worker(name, ns):
        rec = query_dns(domain, ns, timeout)
        return (name, ns, rec)

    print(f"[DNS] 使用 {len(GLOBAL_DNS_SERVERS)} 個公開 DNS 進行查詢:")

    # 多線程查詢
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = [executor.submit(worker, name, ns) for name, ns in GLOBAL_DNS_SERVERS]
        for future in as_completed(tasks, timeout=timeout*len(GLOBAL_DNS_SERVERS)):
            try:
                name, ns, rec = future.result(timeout=timeout)
                print(f"  {name:<12}({ns}):")
                for qt in ['A','AAAA','CNAME','NS']:
                    vals = ', '.join(rec[qt]) if rec[qt] else '[無]'
                    print(f"    {qt:6}: {vals}")
                all_records[ns] = rec
                # 檢查CDN特徵
                for ip in rec.get('A', []):
                    all_ips.add(ip)
                    cdn_type = is_ip_cdn(ip)
                    ip_cdn_map[ip] = bool(cdn_type)
                    if cdn_type:
                        cdn_provs.add(cdn_type)
                cdn_provs |= set(analyze_cdn(rec))
            except Exception as e:
                print(f"  [Timeout or Error] {e}")
    return all_records, all_ips, ip_cdn_map, cdn_provs

def print_dns_report(domain, log_to=None):
    """
    查詢並輸出報告，可選擇將結果寫入 log_manager
    """
    domain = normalize_domain(domain)
    all_records, all_ips, ip_cdn_map, cdn_provs = collect_dns_reports(domain)
    print("\n=== 綜合 DNS/CDN 判斷報告 ===")
    print(f"Domain: {domain}")
    print(f"解析到總共 {len(all_ips)} 個 A 記錄 IP（各地結果綜合）")
    for ip in sorted(all_ips):
        mark = "[CDN]" if ip_cdn_map.get(ip, False) else "[疑似非CDN]"
        print(f"  {ip:<16} {mark}")
    if cdn_provs:
        print(f"\n偵測到 CDN 提供商: {', '.join(sorted(cdn_provs))}")
    else:
        print("\n未發現明顯 CDN 特徵")
    if len(all_ips) > 1:
        print("（多IP，具CDN分流特徵）")
    suspects = [ip for ip, v in ip_cdn_map.items() if not v]
    if suspects:
        print(f"\n[重點] 疑似真實 IP: {', '.join(suspects)}")
    else:
        print("\n未找到明顯非CDN IP")
    # 若帶 log_to 參數，將所有原始查詢與統計寫入 log
    if log_to:
        from src import log_manager
        log_manager.write_dns_log(log_to, {
            "domain": domain,
            "all_records": all_records,
            "all_ips": list(all_ips),
            "ip_cdn_map": ip_cdn_map,
            "cdn_provs": list(cdn_provs),
        })