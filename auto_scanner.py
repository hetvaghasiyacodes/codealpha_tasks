import requests
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init

init(autoreset=True)  # For colored output

# Payload files
XSS_FILE = "xss_payloads.txt"
SQLI_FILE = "sqli_payloads.txt"

# Load payloads from file
def load_payloads(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Payload file {file_path} not found!")
        return []

# Scan parameters of a URL with payloads
def scan_url(url, payloads, scan_type="XSS"):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    if not qs:
        print(f"[INFO] No parameters found in URL: {url}")
        return

    print(f"[{scan_type}] Scanning {url} with {len(payloads)} payloads...\n")
    
    for param in qs:
        for payload in payloads:
            qs_copy = qs.copy()
            qs_copy[param] = payload
            new_query = urlencode(qs_copy, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            try:
                response = requests.get(new_url, timeout=10)
                if payload in response.text:
                    print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} Parameter '{param}'")
                    print(f"Injected URL: {Fore.YELLOW}{new_url}{Style.RESET_ALL}\n")
            except requests.RequestException as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Request failed for {new_url}: {e}")

# Main function
if __name__ == "__main__":
    target_url = input("Enter target URL: ").strip()
    scan_choice = input("Scan type (xss/sqli/all): ").strip().lower()

    if scan_choice in ["xss", "all"]:
        xss_payloads = load_payloads(XSS_FILE)
        scan_url(target_url, xss_payloads, "XSS")
    
    if scan_choice in ["sqli", "all"]:
        sqli_payloads = load_payloads(SQLI_FILE)
        scan_url(target_url, sqli_payloads, "SQLi")
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scan completed.")
