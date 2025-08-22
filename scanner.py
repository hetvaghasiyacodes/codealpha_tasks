import requests
import urllib.parse
import argparse
from colorama import Fore, Style, init
import threading
from queue import Queue
import os

# Initialize colorama
init(autoreset=True)

# Load payloads from file
def load_payloads(file_path):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[ERROR] Payload file not found: {file_path}{Style.RESET_ALL}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# Scan function for XSS
def scan_xss(url, payloads, waf=False):
    print(f"{Fore.CYAN}[XSS] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    vuln_found = False

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            headers = {}
            if waf:
                headers['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64)"
            try:
                r = requests.get(test_url, headers=headers, timeout=10)
                if payload in r.text:
                    vuln_found = True
                    print(f"{Fore.GREEN}[VULNERABLE] XSS found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[PoC URL] {test_url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    if not vuln_found:
        print(f"{Fore.YELLOW}[INFO] No XSS vulnerabilities found.{Style.RESET_ALL}")

# Scan function for SQLi
def scan_sqli(url, payloads, waf=False):
    print(f"{Fore.CYAN}[SQLi] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    vuln_found = False

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            headers = {}
            if waf:
                headers['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64)"
            try:
                r = requests.get(test_url, headers=headers, timeout=10)
                if any(err in r.text.lower() for err in ["mysql", "syntax", "error"]):
                    vuln_found = True
                    backend_info = r.headers.get("Server", "Unknown Backend")
                    print(f"{Fore.GREEN}[VULNERABLE] SQLi found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[PoC URL] {test_url}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[Backend] {backend_info}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    if not vuln_found:
        print(f"{Fore.YELLOW}[INFO] No SQLi vulnerabilities found.{Style.RESET_ALL}")

# Worker thread for queued scanning
def worker(queue, scan_type, xss_payloads, sqli_payloads, waf):
    while not queue.empty():
        url = queue.get()
        if scan_type in ["xss", "all"]:
            scan_xss(url, xss_payloads, waf)
        if scan_type in ["sqli", "all"]:
            scan_sqli(url, sqli_payloads, waf)
        queue.task_done()

def crawl_url(url):
    # Simple crawling placeholder: can be improved with requests + BeautifulSoup
    return [url]  # For now just return the URL itself

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Single target URL with parameters")
    parser.add_argument("-l", "--list", help="File with multiple URLs to scan")
    parser.add_argument("--scan", required=True, choices=["xss","sqli","all"], help="Type of scan")
    parser.add_argument("-waf","--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    parser.add_argument("-t","--threads", type=int, default=4, help="Number of threads")
    args = parser.parse_args()

    print(Fore.GREEN + """
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
""")
    print(Fore.GREEN + "Developed by @hackwithhet")
    print(Fore.YELLOW + "⚠️ WARNING: Only test on targets you own or have permission!\n")

    xss_payloads = load_payloads("xss_payloads.txt")
    sqli_payloads = load_payloads("sqli_payloads.txt")

    urls = []
    if args.url:
        urls.extend(crawl_url(args.url))
    if args.list:
        if os.path.exists(args.list):
            with open(args.list,"r",encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.extend(crawl_url(line))
        else:
            print(f"{Fore.RED}[ERROR] URL list file not found: {args.list}{Style.RESET_ALL}")

    queue = Queue()
    for u in urls:
        queue.put(u)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(queue,args.scan,xss_payloads,sqli_payloads,args.waf_bypass))
        t.start()
        threads.append(t)

    queue.join()
    print(Fore.CYAN + "\n[INFO] Scan completed successfully!" + Style.RESET_ALL)
