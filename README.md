# CDN Piercer

一套破解 CDN 用以輔助查找網站真實 IP 的工具。支援自動計算 favicon hash 並直接用 Shodan 查詢，以及多國 DNS 查詢、CDN 指紋分析與自動記錄報告。

---

## 安裝依賴

建議先安裝 Python 3.7 以上版本。

安裝套件：

```bash
pip install -r requirements.txt
```

未使用過 Shodan CLI 者，首次使用前需設定 Shodan API KEY（註冊並取得 key，然後）：

```bash
shodan init <YOUR_API_KEY>
```

---

## 使用說明

主程式為 `main.py`，常見用法如下：

### 1. 使用網址自動查詢（預設開啟 DNS 分析）

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

---

## 參數一覽

- `-u <URL>`：目標網址，自動下載 favicon 並分析
- `-f <ICON_FILE>`：本機 favicon 檔案
- `-hash <HASH>`：直接查詢指定 hash
- `-dns <DOMAIN|off>`：僅做 DNS 查詢或關閉 DNS
- `-q <SHODAN_Q>`：加上自訂 shodan 查詢語句
- `--no-query`：只算 hash 不查 Shodan
- `-report`：報告模式 (還沒做好)
- `-batch`：批次模式，自動化流程

---

## 查詢結果/日誌

- 每次查詢結果會自動寫入 logs 目錄（包含 DNS 結果、favicon、hash、Shodan 結果等）。

---

## 常見問題

- **Q: shodan CLI 未安裝或找不到？**
  - A: 確認有在 requirements.txt 裡安裝 shodan，並檢查環境變數或重新安裝。
- **Q: API KEY 無效或未設定？**
  - A: 執行 `shodan init <YOUR_API_KEY>`，並確認填入的 key 正確。

---

## 注意事項

- 查詢可能消耗 Shodan credits，請自行管理帳號餘額。
- 適用於安全研究及紅隊合法合規用途，請勿用於未授權滲透。

