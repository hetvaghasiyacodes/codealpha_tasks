import requests
import urllib.parse
import argparse
from colorama import Fore, Style, init
import threading
from queue import Queue
import os
import random
import time

# Tor support
try:
    import socks
    import socket
except ImportError:
    print(f"{Fore.YELLOW}[WARNING] PySocks not installed. Tor will not work.{Style.RESET_ALL}")

# Initialize colorama
init(autoreset=True)

# Random User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/139.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36",
]

# Load payloads from file
def load_payloads(file_path):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[ERROR] Payload file not found: {file_path}{Style.RESET_ALL}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# Set up session with optional Tor and random agent
def get_session(use_tor=False, random_agent=False):
    session = requests.Session()
    headers = {}
    if random_agent:
        headers['User-Agent'] = random.choice(USER_AGENTS)
    session.headers.update(headers)
    
    if use_tor:
        session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
        try:
            r = session.get("http://httpbin.org/ip", timeout=10)
            print(Fore.CYAN + f"[INFO] Tor IP: {r.json()['origin']}" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "[WARNING] Tor not reachable, falling back to normal connection." + Style.RESET_ALL)
            session.proxies = {}
    return session

# Safe GET request with retries
def safe_get(session, url, delay=0, max_retries=3):
    for attempt in range(max_retries):
        try:
            r = session.get(url, timeout=15)
            time.sleep(delay)
            return r
        except Exception as e:
            print(Fore.RED + f"[ERROR] {e} (Attempt {attempt+1}/{max_retries})" + Style.RESET_ALL)
            time.sleep(2)
    return None

# Scan function for XSS
def scan_xss(url, payloads, session, waf=False, delay=0):
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
            r = safe_get(session, test_url, delay)
            if r and payload in r.text:
                vuln_found = True
                print(f"{Fore.GREEN}[VULNERABLE] XSS found with payload: {payload}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}[PoC URL] {test_url}{Style.RESET_ALL}")

    if not vuln_found:
        print(f"{Fore.YELLOW}[INFO] No XSS vulnerabilities found.{Style.RESET_ALL}")

# Scan function for SQLi
def scan_sqli(url, payloads, session, waf=False, delay=0):
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
            r = safe_get(session, test_url, delay)
            if r and any(err in r.text.lower() for err in ["mysql", "syntax", "error"]):
                vuln_found = True
                backend_info = r.headers.get("Server", "Unknown Backend")
                print(f"{Fore.GREEN}[VULNERABLE] SQLi found with payload: {payload}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}[PoC URL] {test_url}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[Backend] {backend_info}{Style.RESET_ALL}")

    if not vuln_found:
        print(f"{Fore.YELLOW}[INFO] No SQLi vulnerabilities found.{Style.RESET_ALL}")

# Worker thread for queued scanning
def worker(queue, scan_type, xss_payloads, sqli_payloads, session, waf, delay):
    while not queue.empty():
        url = queue.get()
        if scan_type in ["xss", "all"]:
            scan_xss(url, xss_payloads, session, waf, delay)
        if scan_type in ["sqli", "all"]:
            scan_sqli(url, sqli_payloads, session, waf, delay)
        queue.task_done()

# Basic crawl placeholder
def crawl_url(url):
    # Can integrate BeautifulSoup or Scrapy later
    return [url]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Single target URL with parameters")
    parser.add_argument("-l", "--list", help="File with multiple URLs to scan")
    parser.add_argument("--scan", required=True, choices=["xss","sqli","all"], help="Type of scan")
    parser.add_argument("-waf","--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    parser.add_argument("-t","--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--tor", action="store_true", help="Route requests through Tor network")
    parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent per request")
    parser.add_argument("--delay", type=float, default=0, help="Delay per request in seconds")
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

    session = get_session(use_tor=args.tor, random_agent=args.random_agent)

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
        t = threading.Thread(target=worker, args=(queue,args.scan,xss_payloads,sqli_payloads,session,args.waf_bypass,args.delay))
        t.start()
        threads.append(t)

    queue.join()
    print(Fore.CYAN + "\n[INFO] Scan completed successfully!" + Style.RESET_ALL)
