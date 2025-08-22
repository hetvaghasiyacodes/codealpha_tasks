import requests
import urllib.parse
import argparse
from colorama import Fore, Style, init
import random
import threading
from queue import Queue

# Initialize colorama
init(autoreset=True)

# ---------------------------
# Banner, Developer & Warning
# ---------------------------
banner = r"""
   ____          _      _    _ _       _       
  / ___|___   __| | ___| | _(_) |_ ___| |__    
 | |   / _ \ / _` |/ _ \ |/ / | __/ __| '_ \   
 | |__| (_) | (_| |  __/   <| | || (__| | | |  
  \____\___/ \__,_|\___|_|\_\_|\__\___|_| |_|  

        _   _      _   _                              
       | | | | ___| |_| |__   ___  _ __   ___ _ __    
       | |_| |/ _ \ __| '_ \ / _ \| '_ \ / _ \ '__|   
       |  _  |  __/ |_| | | | (_) | | | |  __/ |      
       |_| |_|\___|\__|_| |_|\___/|_| |_|\___|_|      
"""
print(Fore.CYAN + banner)
print(Fore.GREEN + "Developed by @hackwithhet\n")
print(Fore.RED + "⚠️ WARNING: Only use this tool on targets you own or have explicit permission to test. Unauthorized use is illegal!\n" + Style.RESET_ALL)

# ---------------------------
# Headers & Agents
# ---------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Safari/605.1.15"
]

def random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

# ---------------------------
# Scanners
# ---------------------------
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
                r = requests.get(test_url, headers=random_headers(), timeout=7)
                if payload in r.text:
                    print(f"{Fore.GREEN}[VULNERABLE] XSS found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

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
                r = requests.get(test_url, headers=random_headers(), timeout=7)
                lower_text = r.text.lower()
                if "mysql" in lower_text or "syntax" in lower_text or "error" in lower_text:
                    print(f"{Fore.GREEN}[VULNERABLE] SQL Injection found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[BACKEND INFO] {lower_text[:200]}...{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

# ---------------------------
# Worker for threading
# ---------------------------
def worker(q, scan_type, xss_payloads, sqli_payloads):
    while not q.empty():
        url = q.get()
        if scan_type in ["xss", "all"]:
            scan_xss(url, xss_payloads)
        if scan_type in ["sqli", "all"]:
            scan_sqli(url, sqli_payloads)
        q.task_done()

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Single target URL with parameters")
    parser.add_argument("-l", "--list", help="Path to file with URLs to scan")
    parser.add_argument("--scan", required=True, choices=["xss", "sqli", "all"], help="Type of scan")
    parser.add_argument("-waf", "--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for scanning")
    args = parser.parse_args()

    # Load payloads
    with open("xss_payloads.txt") as f:
        xss_payloads = [line.strip() for line in f if line.strip()]
    with open("sqli_payloads.txt") as f:
        sqli_payloads = [line.strip() for line in f if line.strip()]

    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        with open(args.list) as f:
            urls.extend([line.strip() for line in f if line.strip()])

    queue = Queue()
    for u in urls:
        queue.put(u)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(queue, args.scan, xss_payloads, sqli_payloads))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(Fore.GREEN + "\nScan completed successfully!" + Style.RESET_ALL)
