import os
import argparse

# ------------------------
# XSS Scanner Function
# ------------------------
def scan_xss(url):
    payload_file = os.path.join("payloads", "xss.txt")
    
    print(f"[XSS] Reading payloads from {payload_file}")
    try:
        with open(payload_file, "r") as f:
            payloads = f.read().splitlines()
    except FileNotFoundError:
        print("[XSS] Payload file not found! Skipping XSS scan.")
        return

    print(f"[XSS] Found {len(payloads)} payloads. Starting scan...")
    for payload in payloads:
        # Example logic: print payload (replace with real scanning later)
        print(f"[XSS] Testing payload: {payload} on {url}")


# ------------------------
# SQLi Scanner Function
# ------------------------
def scan_sqli(url):
    payload_file = os.path.join("payloads", "sqli.txt")
    
    print(f"[SQLi] Reading payloads from {payload_file}")
    try:
        with open(payload_file, "r") as f:
            payloads = f.read().splitlines()
    except FileNotFoundError:
        print("[SQLi] Payload file not found! Skipping SQLi scan.")
        return

    print(f"[SQLi] Found {len(payloads)} payloads. Starting scan...")
    for payload in payloads:
        # Example logic: print payload (replace with real scanning later)
        print(f"[SQLi] Testing payload: {payload} on {url}")


# ------------------------
# CLI Entry Point
# ------------------------
def main():
    parser = argparse.ArgumentParser(description="🚀 CodeAlpha Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("--scan", choices=["xss", "sqli", "all"], default="all", help="Type of scan")
    args = parser.parse_args()

    url = args.url
    scan_type = args.scan

    print(f"[INFO] Scanning {url} for {scan_type.upper()} vulnerabilities...")

    if scan_type in ["xss", "all"]:
        scan_xss(url)
    if scan_type in ["sqli", "all"]:
        scan_sqli(url)


if __name__ == "__main__":
    main()
