import os
import argparse

# ---------------------------
# File paths (auto root folder)
# ---------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
XSS_PAYLOAD_FILE = os.path.join(BASE_DIR, "xss_payloads.txt")
SQLI_PAYLOAD_FILE = os.path.join(BASE_DIR, "sqli_payloads.txt")

# ---------------------------
# Argument parser
# ---------------------------
parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
parser.add_argument("-u", "--url", required=True, help="Target URL")
parser.add_argument("--scan", choices=["xss", "sqli", "all"], default="all", help="Scan type")
args = parser.parse_args()

url = args.url
scan_type = args.scan.lower()

# ---------------------------
# Load payloads function
# ---------------------------
def load_payloads(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Payload file not found: {file_path}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# ---------------------------
# Scanning functions
# ---------------------------
def scan_xss(target):
    payloads = load_payloads(XSS_PAYLOAD_FILE)
    if not payloads:
        print("[XSS] No payloads found, skipping XSS scan.")
        return
    print(f"[XSS] Scanning {target} with {len(payloads)} payloads...")
    for payload in payloads:
        print(f"[XSS] Testing payload: {payload}")

def scan_sqli(target):
    payloads = load_payloads(SQLI_PAYLOAD_FILE)
    if not payloads:
        print("[SQLi] No payloads found, skipping SQLi scan.")
        return
    print(f"[SQLi] Scanning {target} with {len(payloads)} payloads...")
    for payload in payloads:
        print(f"[SQLi] Testing payload: {payload}")

# ---------------------------
# Main
# ---------------------------
if scan_type == "xss":
    scan_xss(url)
elif scan_type == "sqli":
    scan_sqli(url)
else:
    scan_xss(url)
    scan_sqli(url)
