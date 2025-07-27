# CDN Piercer

一套破解 CDN 用以輔助查找網站真實 IP 的工具。支援自動計算 favicon hash 並直接用 Shodan 查詢，以及多國 DNS 查詢、CDN 指紋分析與自動記錄報告。

---

## 安裝方式

建議在 Python 3.8+ 環境下，安裝依賴：

```bash
pip install -r requirements.txt
```

Shodan CLI 需設置 API KEY：

```bash
pip install shodan
shodan init <Your-API-Key>
```

---

## 使用方法

### 1. 基本用法

```bash
python main.py -u https://example.com
```

- 會自動獲取 favicon、計算 hash、執行 Shodan 查詢，並進行多地 DNS 分析。

### 2. 指定本機 icon 檔案查詢

```bash
python main.py -f favicon.ico
```

- 直接以本機 icon 檔案計算 hash 並查詢。

### 3. 已知 hash 直接查詢

```bash
python main.py -hash <hash>
```

### 4. 只做 DNS 多國查詢，不查 Shodan

```bash
python main.py -dns example.com
```

### 5. 關閉 DNS 分析（只查 favicon）

```bash
python main.py -u https://example.com -dns off
```

### 6. 加入 Shodan 額外查詢條件

```bash
python main.py -u https://example.com -q 'port:8080 country:JP'
```

### 7. 只算 hash 不查 Shodan

```bash
python main.py -u https://example.com --no-query
```


### 常用參數

| 參數               | 功能說明                     |
| ---------------- | ------------------------ |
| `-u <url>`       | 分析指定網址                   |
| `-f <icon_file>` | 指定本地 icon 檔案             |
| `-hash <hash>`   | 直接指定 hash 查詢             |
| `-dns <domain>`  | 只執行 DNS 查詢               |
| `-report`        | 歷史報告模式                   |
| `--no-query`     | 不查 Shodan，只輸出特徵與 hash    |
| `-q <條件>`        | 附加 Shodan 查詢條件           |
| `-batch`         | 批次模式，所有流程自動化             |
| `--apikey <KEY>` | 直接指定 Shodan HTTP API Key |

---

## 注意事項

- 推薦先檢查 `requirements.txt` 內依賴項版本，避免與其他安全工具衝突。
- 使用 Shodan 前請先申請並設定有效的 API Key。
- 查詢可能消耗 Shodan credits，請自行管理帳號餘額。
- 適用於安全研究及紅隊合法合規用途，請勿用於未授權滲透。
