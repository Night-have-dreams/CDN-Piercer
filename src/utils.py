import base64
import mmh3

def calc_favicon_hash(data_bytes):
    """
    Shodan/CTF 標準做法：用 base64.encodebytes（包含換行）再 decode utf-8。
    """
    b64str = base64.encodebytes(data_bytes).decode('utf-8')  # 注意：不是 b64encode！
    return mmh3.hash(b64str)
