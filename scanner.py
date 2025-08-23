import requests
import argparse

# Payload lists
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", '" OR ""="']
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']

def scan_sql_injection(url):
    print(f"\n[SQLi] Scanning {url} with {len(SQLI_PAYLOADS)} payloads...")
    for payload in SQLI_PAYLOADS:
        test_url = url.replace("FUZZ", payload)
        try:
            r = requests.get(test_url, timeout=10)
            if "error" in r.text.lower() or "mysql" in r.text.lower() or "syntax" in r.text.lower():
                print(f"[VULNERABLE] {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")

def scan_xss(url):
    print(f"\n[XSS] Scanning {url} with {len(XSS_PAYLOADS)} payloads...")
    for payload in XSS_PAYLOADS:
        test_url = url.replace("FUZZ", payload)
        try:
            r = requests.get(test_url, timeout=10)
            if payload in r.text:
                print(f"[VULNERABLE] {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")

def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner by @hackwithhet")
    parser.add_argument("-u", "--url", help="Target URL with FUZZ keyword", required=True)
    parser.add_argument("--scan", choices=["sqli", "xss", "all"], default="all", help="Choose scan type")
    args = parser.parse_args()

    print("\n   ____          _      _    _ _       _")
    print("  / ___|___   __| | ___| | _(_) |_ ___| |__")
    print(" | |   / _ \ / _` |/ _ \ |/ / | __/ __| '_ \\")
    print(" | |__| (_) | (_| |  __/   <| | || (__| | | |")
    print("  \\____\\___/ \\__,_|\\___|_|\\_\\_|\\__\\___|_| |_|")
    print("\nDeveloped by @hackwithhet")
    print("⚠️ WARNING: Only test on targets you own or have permission!\n")

    if args.scan in ["sqli", "all"]:
        scan_sql_injection(args.url)

    if args.scan in ["xss", "all"]:
        scan_xss(args.url)

if __name__ == "__main__":
    main()
