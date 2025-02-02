import os
import json
import requests
from bs4 import BeautifulSoup
import re
import sys
import threading
import logging
from urllib.parse import urljoin, urlparse
from tabulate import tabulate
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import math
import time

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(filename='Morgan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
CACHE_DIR = 'Caches'
JS_FILES_DIR_BASE = 'JSFiles'
DEFAULT_TIMEOUT = 5
DEFAULT_ENTROPY_THRESHOLD = 4.5
DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
]

# Enhanced Patterns
PATTERNS = {
    'API Key': r'(api_key|apiKey|apikey|client_id|clientId|access_token|token|apiToken)[\s]*[:=][\s]*[\'"]([a-zA-Z0-9-_]{32,})[\'"]',
    'API Secret': r'(api_secret|secret_key|apiSecret|apiKey)[\s]*[:=][\s]*[\'"]([a-zA-Z0-9-_]{32,})[\'"]',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Access Key': r'aws_secret_access_key[\s]*[:=][\s]*[\'"]([a-zA-Z0-9/+=]{40,})[\'"]',
    'GitHub Token': r'gh[pousr]_[0-9a-zA-Z]{36}',
    'GitLab Token': r'glpat-[a-zA-Z0-9]{20}',
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,}',
    'Stripe Key': r'(sk_live|pk_live)_[0-9a-zA-Z]{24}',
    'PayPal Key': r'AY[0-9a-zA-Z]{32}',
    'OpenAPI Key': r'(?:openapi\.key|openai\.key)[\s]*[:=][\s]*[\'"]([^\s\'"]{32,})[\'"]',
    'GitHub Repo': r'github\.com\/[a-zA-Z0-9_\-\/]+\/[a-zA-Z0-9_\-]+',
    'JWT Token': r'eyJ[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\.[0-9A-Za-z-_]{43,}',  # Token should be 43+ chars after the 3rd part
    'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
    'Database Connection': r'(mongodb:\/\/|mysql:\/\/|postgres:\/\/|redis:\/\/|sqlite:\/\/)[^\s\'"]+',
    'MongoDB Password': r'(?:mongodb\.password|mongo\.password)[\s]*[:=][\s]*[\'"]([^\s\'"]{8,})[\'"]',
    'Redis Password': r'(?:redis\.password|redis\.auth)[\s]*[:=][\s]*[\'"]([^\s\'"]{8,})[\'"]',
    'ElasticSearch Password': r'(?:elasticsearch\.password|elastic\.password)[\s]*[:=][\s]*[\'"]([^\s\'"]{8,})[\'"]',
    'SMTP Password': r'(?:smtp\.password|smtp\.auth)[\s]*[:=][\s]*[\'"]([^\s\'"]{8,})[\'"]',
    'Session ID': r'session_id[\s]*[:=][\s]*[\'"]([a-zA-Z0-9-_]{16,})[\'"]',
    'Authorization Token': r'(Bearer|Token|X-Auth-Token|Api-Token|access_token)[\s]*[:=][\s]*[\'"]([a-zA-Z0-9-_]{32,})[\'"]',
    'IP Address': r'(?:\d{1,3}\.){3}\d{1,3}',
    'URLs': r'(http[s]?:\/\/(?:www\.)?[a-zA-Z0-9.-]+(?:\/[^\s]*)?)',
    'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Private Key': r'-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----([^\-]+)-----END (RSA|EC|DSA|PRIVATE) KEY-----',
    'High Entropy String': r'[A-Za-z0-9+/]{40,}',  # Entropy-based strings like long random tokens
    'Password': r'(password|pass|pwd|passwd)[\s]*[:=][\s]*[\'"]([^\s\'"]{8,})[\'"]',
    'GitLab Repo': r'gitlab\.com\/[a-zA-Z0-9_\-\/]+\/[a-zA-Z0-9_\-]+',
    'Facebook App ID': r'[0-9]{15,}',
    'Salesforce Token': r'00D[0-9A-Z]{12}',
    'JIRA Token': r'JIRA-[A-Z]{2,}-\d{1,5}',
    'Webhook Secret': r'webhook_secret[\s]*[:=][\s]*[\'"]([a-zA-Z0-9-_]{32,})[\'"]',
    'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
    'Twilio API Key': r'AC[a-f0-9]{32}',
    'Zoom API Key': r'AIza[0-9A-Za-z_-]{35}',
    'Twitch API Key': r'oauth:[a-f0-9]{30}',
    'Telegram Bot Token': r'[0-9]{9}:[a-zA-Z0-9_-]{35}',
    'Twitter Bearer Token': r'Bearer\s[0-9a-zA-Z]{40}',
    'Slack App Token': r'xox[a-zA-Z0-9]+-[0-9a-zA-Z]+-[a-zA-Z0-9]+',
    'MongoDB URI': r'mongodb:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+)(?::\d+)?(?:\/[a-zA-Z0-9_]+)?',
    'SSH Private Key': r'-----BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----([^\-]+)-----END (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----',
    'Basic Auth': r'Authorization:\s*Basic\s+[A-Za-z0-9+\/=]{20,}',
    'API Key Parameter': r'[?&](api_key|access_token|apikey|client_secret|client_id)=[a-zA-Z0-9-_]{10,}',
    'AWS API Key': r'AKIA[0-9A-Z]{16}|[0-9a-zA-Z/+=]{40}',
}

# Utility functions

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def is_high_entropy_string(s, threshold=DEFAULT_ENTROPY_THRESHOLD):
    return calculate_entropy(s) > threshold

def fetch_page(url, timeout=DEFAULT_TIMEOUT, retries=3, delay=1, user_agent=None):
    headers = {'User-Agent': user_agent or DEFAULT_USER_AGENTS[0]}
    while retries > 0:
        try:
            print(f"{Fore.CYAN}Fetching: {url}{Style.RESET_ALL}")
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            logging.info(f'Successfully fetched {url}')
            return response.text
        except requests.RequestException as e:
            logging.error(f'Error fetching {url}: {e}')
            retries -= 1
            if retries > 0:
                print(f"{Fore.YELLOW}Retrying ({retries} retries left) after delay of {delay}s...{Style.RESET_ALL}")
                logging.info(f'Retrying {url} ({retries} retries left) after delay of {delay}s')
                time.sleep(delay)
    print(f"{Fore.RED}Failed to fetch {url}{Style.RESET_ALL}")
    return None

def extract_js_files(html, base_url):
    if not html:
        print(f"{Fore.RED}Empty HTML content.{Style.RESET_ALL}")
        return []

    soup = BeautifulSoup(html, 'html.parser')
    js_files = [urljoin(base_url, script['src']) for script in soup.find_all('script', src=True)]

    if not js_files:
        print(f"{Fore.YELLOW}No JavaScript files found on the page.{Style.RESET_ALL}")

    return js_files

def detect_obfuscation(js_code):
    obfuscation_indicators = [
        r'eval\(', r'document\.write\(', r'Function\(', r'atob\(', r'btoa\(',
        r'unescape\(', r'setTimeout\(', r'setInterval\(', r'\\x[a-fA-F0-9]{2}',  # Hexadecimal encoding
        r'(?:[\w\d_$]+\s*=\s*[\w\d_$]+\s*\+\s*){3,}',  # String concatenation pattern
        r'0x[0-9a-fA-F]+'  # Hexadecimal numbers
    ]
    findings = []
    for pattern in obfuscation_indicators:
        if re.search(pattern, js_code):
            findings.append(f"Obfuscation pattern detected: {pattern}")
    return findings

def analyze_js(js_url, patterns=None, entropy_threshold=DEFAULT_ENTROPY_THRESHOLD):
    js_code = fetch_page(js_url)
    if not js_code:
        return []

    findings = []
    obfuscation_findings = detect_obfuscation(js_code)
    findings.extend([('Obfuscation Detected', pattern) for pattern in obfuscation_findings])

    for key, pattern in (patterns or PATTERNS).items():
        matches = re.findall(pattern, js_code)
        if matches:
            # Flatten tuples if they exist
            if isinstance(matches[0], tuple):
                matches = [item for sublist in matches for item in sublist]  # Flatten the list of tuples
            findings.append((key, ', '.join(matches)))

    # Entropy-based detection
    for match in re.findall(r'[A-Za-z0-9+/]{40,}', js_code):
        if is_high_entropy_string(match, threshold=entropy_threshold):
            findings.append(('High Entropy String', match))

    return findings

def cache_results(url, results):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    hostname = extract_hostname(url)
    if not hostname:
        logging.error(f"Invalid URL: {url}")
        return

    filename = hostname.replace('.', '_') + '.json'
    filepath = os.path.join(CACHE_DIR, filename)

    with open(filepath, 'w') as f:
        json.dump(results, f, indent=4)

def load_cached_results(url):
    hostname = extract_hostname(url)
    if not hostname:
        logging.error(f"Invalid URL: {url}")
        return None

    filename = hostname.replace('.', '_') + '.json'
    filepath = os.path.join(CACHE_DIR, filename)

    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

def extract_hostname(url):
    parsed_url = urlparse(url)
    if not parsed_url.hostname:
        return None
    return parsed_url.hostname

def print_results(js_url, findings, filters=None):
    if filters:
        findings = [f for f in findings if f[0] in filters]

    print(f'\n{Fore.GREEN}[URL] {js_url}{Style.RESET_ALL}')
    if findings:
        table = []
        for key, value in findings:
            if len(value) > 100:
                value = value[:100] + '... [TRUNCATED]'
            table.append([key, value])
        print(tabulate(table, headers=['Part', 'Details'], tablefmt='fancy_grid'))
    else:
        print(f'{Fore.RED}[Credentials] Not Found{Style.RESET_ALL}')

def download_js(js_url, target_dir):
    os.makedirs(target_dir, exist_ok=True)  # Ensure the directory exists, and if it does, don't raise an error

    js_code = fetch_page(js_url)
    if not js_code:
        return

    filename = os.path.join(target_dir, urlparse(js_url).path.replace('/', '_').strip('_') + '.js')
    with open(filename, 'w') as f:
        f.write(js_code)
    logging.info(f'Downloaded {js_url} to {filename}')

def fetch_csp(url):
    try:
        response = requests.head(url)
        csp_header = response.headers.get('Content-Security-Policy', '')
        return csp_header
    except requests.RequestException as e:
        logging.error(f"Failed to fetch CSP: {e}")
        return None

def analyze_csp(csp_header):
    if not csp_header:
        print(f'{Fore.RED}[CSP] No Content-Security-Policy found{Style.RESET_ALL}')
        return

    print(f'{Fore.CYAN}[CSP] Content-Security-Policy Detected: {csp_header}{Style.RESET_ALL}')
    if "unsafe-inline" in csp_header:
        print(f'{Fore.RED}[Weak CSP] Usage of unsafe-inline detected!{Style.RESET_ALL}')
    if "unsafe-eval" in csp_header:
        print(f'{Fore.RED}[Weak CSP] Usage of unsafe-eval detected!{Style.RESET_ALL}')

def read_list_from_file(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {filename}{Style.RESET_ALL}")
        sys.exit(1)

def deep_scan(urls, user_agents, depth=3, max_depth=3, use_cache=True, filters=None, download=False, timeout=DEFAULT_TIMEOUT, entropy_threshold=DEFAULT_ENTROPY_THRESHOLD):
    for url in urls:
        hostname = extract_hostname(url)
        if not hostname:
            print(f"{Fore.RED}Invalid URL: {url}{Style.RESET_ALL}")
            continue

        if use_cache and not download:
            cached_results = load_cached_results(url)
            if cached_results:
                print(f'{Fore.CYAN}[Cached Results]{Style.RESET_ALL}')
                for js_url, findings in cached_results.items():
                    print_results(js_url, findings, filters)
                continue

        base_url = urlparse(url).scheme + '://' + urlparse(url).hostname
        html = fetch_page(url, timeout=timeout, user_agent=user_agents[0] if user_agents else None)
        if not html:
            continue

        csp_header = fetch_csp(url)
        analyze_csp(csp_header)

        js_files = extract_js_files(html, base_url)
        print(f'\n{Fore.CYAN}[ JS Files ]{Style.RESET_ALL}')
        for js_file in js_files:
            print(f'- {Fore.YELLOW}{js_file}{Style.RESET_ALL}')

        if not js_files:
            continue

        results = {}

        # Multi-threaded analysis of JavaScript files
        with ThreadPoolExecutor() as executor:
            # For scanning JS files
            scan_futures = [executor.submit(analyze_js, js_file, PATTERNS, entropy_threshold) for js_file in js_files]
            scan_results = []

            for future in scan_futures:
                findings = future.result()
                scan_results.append(findings)

            # Print scan results
            for i, findings in enumerate(scan_results):
                js_file = js_files[i]
                print_results(js_file, findings, filters)
                results[js_file] = findings

            # For downloading JS files (if requested)
            if download:
                target_dir = os.path.join(JS_FILES_DIR_BASE, hostname)
                download_futures = [executor.submit(download_js, js_file, target_dir) for js_file in js_files]
                for future in download_futures:
                    future.result()

        if use_cache:
            cache_results(url, results)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'{Fore.RED}Usage: python Morgan.py <URL|URL list file> [--user-agent-file <file>] [--no-cache] [--download] [--timeout N] [--filter pattern1 pattern2 ...] [--entropy threshold]{Style.RESET_ALL}')
        sys.exit(1)

    url_arg = sys.argv[1]
    user_agent_file = None
    no_cache = '--no-cache' in sys.argv
    download = '--download' in sys.argv
    timeout = DEFAULT_TIMEOUT
    filters = None
    entropy_threshold = DEFAULT_ENTROPY_THRESHOLD

    # Handle optional arguments
    if '--user-agent-file' in sys.argv:
        user_agent_file = sys.argv[sys.argv.index('--user-agent-file') + 1]

    if '--timeout' in sys.argv:
        timeout_idx = sys.argv.index('--timeout') + 1
        timeout = int(sys.argv[timeout_idx])

    if '--filter' in sys.argv:
        filter_idx = sys.argv.index('--filter') + 1
        filters = sys.argv[filter_idx:filter_idx + 5]  # Extract up to 5 patterns to filter

    if '--entropy' in sys.argv:
        entropy_idx = sys.argv.index('--entropy') + 1
        entropy_threshold = float(sys.argv[entropy_idx])

    # Load URL and User-Agent list
    urls = [url_arg] if not os.path.isfile(url_arg) else read_list_from_file(url_arg)
    user_agents = DEFAULT_USER_AGENTS if not user_agent_file else read_list_from_file(user_agent_file)

    deep_scan(urls, user_agents, use_cache=not no_cache, download=download, timeout=timeout, filters=filters, entropy_threshold=entropy_threshold)
