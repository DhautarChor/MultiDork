
# 🔍 Dork Utility Toolkit by DhautarChor 💀

A powerful all-in-one OSINT & vulnerability scanning toolkit built in Python — tailored for ethical hackers, bug bounty hunters, and penetration testers! 💣  
Easily generate Google dorks, test for SQLi, scan URLs, and even integrate with **SQLMap v2** — all from a single script! 🧠⚙️

---

## 🧰 Features

### 🎯 1. Generate Dorks  
- Create powerful Google dorks with:  
  - 🔑 Keywords (`password`, `config`, etc.)  
  - 📁 Filetypes (`.sql`, `.env`, `.log`, etc.)  
  - 🔗 URL patterns (`admin`, `cpanel`, etc.)  
  - 🧾 Titles (`login`, `dashboard`, etc.)  
- Supports custom entries via `keywords.txt`

### 🌐 2. Convert Dorks to Search URLs  
- Converts dorks into search URLs for:  
  🔎 Google | 🐦 Bing | 🦆 DuckDuckGo | 🧭 Yandex

### ✅ 3. Test Dorks for Live Results  
- Validates dorks by checking search engine responses  
- Saves status: `[OK]`, `[NO]`, or `[ERROR]`

### 🔓 4. Scan for Vulnerabilities  
- Detects common web vulns in dorked URLs:  
  🐛 SQL Injection (SQLi)  
  🚨 Cross-Site Scripting (XSS)  
  🔍 Local File Inclusion (LFI)  
- Saves results in `vuln_test_results.txt`

### 📂 5. Auto Keyword File Handling  
- Auto-generates or restores `keywords.txt` if missing

### 🧠 6. Deep SQL Injection Scanner  
- Launches advanced payloads like:  
  `' OR 1=1--`, `"; WAITFOR DELAY...`, `' AND SLEEP(5)--+`  
- Results saved in `deep_sqli_results.txt`

### 🧪 7. SQLMap v2 Integration (🔥 New)  
- Automatically runs **SQLMap v2** on all `[VULNERABLE]` URLs  
- Uses enhanced flags for deeper, smarter testing:
  ```
  --batch --level=5 --risk=3 --crawl=2 --random-agent --flush-session
  ```
- Output logs saved per target in `sqlmap_v2_output/`

---

## 🚀 How to Run

```bash
python dork_toolkit_with_sqlmap.py
```

🔸 Requires:
- Python 3.x  
- SQLMap v2 (install via pip or GitHub)  
- Internet connection for testing live queries

---

## 👨‍💻 Developer

Made with 💻 and a little chaos by **DhautarChor**
