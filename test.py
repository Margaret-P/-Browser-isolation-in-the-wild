import csv
import json
import time
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import InvalidSessionIdException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
from tqdm import tqdm

start_time = time.time()

# CONFIGURATION
# SITES = [ # takes around 1 minute to run these sites 
#     'https://example.com',
#     'https://github.com',
#     'https://wikipedia.org',
#     'https://youtube.com',
#     'https://facebook.com',
# ]
SITES = []   # take first 5000 from top-1m.csv

with open('top-1m.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)  # skip header row
    for i, row in enumerate(reader):
        if i >= 5000:
            break
        SITES.append(row[1])  # URL in the second column

OUTPUT_FILE = 'results.csv'
HEADLESS = True          # controlls if browser shown or not
WAIT_TIME = 10           # 10 seconds ideal
MAX_CONSECUTIVE_TIMEOUTS = 3   # restart driver consecutive timeouts
RESTART_EVERY = 500      # restart Chrome to prevent memory bloat
REACHABILITY_TIMEOUT = 5  # seconds for the pre-flight HEAD request

# Security headers to track
HEADERS = [
    'cross-origin-opener-policy',    # COOP  – window/tab isolation
    'cross-origin-embedder-policy',  # COEP  – embedded resource requirements
    'cross-origin-resource-policy',  # CORP  – who can load this resource
    'content-security-policy',       # CSP   – overall content security
    'x-frame-options',               # XFO   – clickjacking protection
]

# HELPERS
def create_driver(): # set up selenium chrome driver
    print("Setting up browser")
    options = Options()
    if HEADLESS:
        options.add_argument('--headless=new')

    # Stability / memory options
    options.add_argument('--disable-dev-shm-usage')   # avoid /dev/shm OOM crashes?
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-images')
    options.add_argument('--blink-settings=imagesEnabled=false')
    options.add_argument('--js-flags=--max-old-space-size=512')  # cap JS heap 512 MB

    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    options.add_experimental_option('perfLoggingPrefs', {'enableNetwork': True})

    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=options)


def is_session_error(exc_or_msg: str) -> bool: # driver session died
    keywords = ['invalid session id', 'no such session', 'session deleted']
    text = exc_or_msg.lower()
    return any(k in text for k in keywords)


def is_timeout_or_crash(status: str) -> bool: # status crash
    bad_signals = [
        'HTTPConnectionPool',
        'Read timed out',
        'invalid session id',
        'no such session',
        'session deleted',
    ]
    return any(s.lower() in status.lower() for s in bad_signals)


def sanitize_url(domain: str): # normalize urls
    domain = domain.strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        url = domain
    else:
        url = 'https://' + domain

    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    if re.search(r'[\s<>"{}|\\^`]', url):
        return None
    return url


def is_site_reachable(url: str, timeout: int = REACHABILITY_TIMEOUT) -> bool: # check if site is even up
    try:
        r = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'},
        )
        return r.status_code < 500
    except Exception:
        return False

#
csv_headers = [
    'Parent_URL', 'Page_Type', 'URL',
    'COOP', 'COEP', 'CORP', 'CSP', 'XFO',
    'Iframe_Count', 'Cross_Origin_Iframes', 'Sandboxed_Iframes',
    'Status',
]


# extraction here
def extract_page_data(driver, target_url, parent_url, page_type):
    """
    Navigate to target_url, capture security response headers and iframe stats.
    Returns (row_dict, BeautifulSoup | None).
    Raises InvalidSessionIdException / WebDriverException so the caller can decide whether to restart the driver.
    """
    print(f"  [{page_type}] {target_url}")

    row_data = {col: 'Not present' for col in csv_headers}
    row_data['Parent_URL'] = parent_url
    row_data['Page_Type'] = page_type
    row_data['URL'] = target_url
    row_data['Iframe_Count'] = '0'
    row_data['Cross_Origin_Iframes'] = '0'
    row_data['Sandboxed_Iframes'] = '0'

    # Clear previous performance logs, navigate
    driver.get_log('performance')
    driver.get(target_url)

    # Response headers from performance log 
    logs = driver.get_log('performance')
    resp_headers = {}

    for log in logs:
        message = json.loads(log['message'])
        method = message.get('message', {}).get('method', '')

        if method == 'Network.responseReceived':
            params = message['message']['params']
            resp_url = params.get('response', {}).get('url', '')

            if target_url.strip('/') in resp_url:
                raw = params.get('response', {}).get('headers', {})
                resp_headers = {k.lower(): v for k, v in raw.items()}
                break

    row_data['COOP'] = resp_headers.get('cross-origin-opener-policy', 'Not present')
    row_data['COEP'] = resp_headers.get('cross-origin-embedder-policy', 'Not present')
    row_data['CORP'] = resp_headers.get('cross-origin-resource-policy', 'Not present')
    row_data['CSP']  = resp_headers.get('content-security-policy', 'Not present')
    row_data['XFO']  = resp_headers.get('x-frame-options', 'Not present')

    # Iframes
    soup = BeautifulSoup(driver.page_source, 'html.parser')
    iframes = soup.find_all('iframe')
    row_data['Iframe_Count'] = str(len(iframes))

    current_domain = urlparse(target_url).netloc
    co_count = sb_count = 0

    for ifr in iframes:
        src = str(ifr.get('src', ''))
        if src.startswith('http') and current_domain not in src:
            co_count += 1
        if ifr.has_attr('sandbox'):
            sb_count += 1

    row_data['Cross_Origin_Iframes'] = str(co_count)
    row_data['Sandboxed_Iframes'] = str(sb_count)
    row_data['Status'] = 'Success'

    return row_data, soup


def safe_extract(driver, target_url, parent_url, page_type): # catch errors, return error instead of crash
    """
    Wrapper around extract_page_data to catch WebDriver exceptions.
    If sessionr elated error is detected, it raises the exception to trigger a driver restart.
    For other exceptions, it returns a row with the error message in the Status field.
    """
    try:
        return extract_page_data(driver, target_url, parent_url, page_type)
    except (InvalidSessionIdException, WebDriverException) as e:
        if is_session_error(str(e)):
            raise  # let the outer loop restart the driver
        # if non  session WebDriver error, continue
        row_data = {col: 'Not present' for col in csv_headers}
        row_data.update({'Parent_URL': parent_url, 'Page_Type': page_type,
                         'URL': target_url, 'Status': f'Error: {str(e)[:50]}'})
        return row_data, None
    except Exception as e:
        row_data = {col: 'Not present' for col in csv_headers}
        row_data.update({'Parent_URL': parent_url, 'Page_Type': page_type,
                         'URL': target_url, 'Status': f'Error: {str(e)[:50]}'})
        return row_data, None


def call_with_session_recovery(driver_ref: list, target_url, parent_url, page_type): # restart if error happens
    """
    Calls safe_extract and handles session related errors by restarting the driver once.
        - driver_ref is a list with the driver instance, allowing to swap it by reference if needed.
        - If a session error is detected on the first attempt, it restarts the driver and retries once.
        - If it fails again, it returns a row indicating the session crash without further retries to avoid infinite loops. 
        - For non session errors, returns the error status without retrying.
    """
    for attempt in range(2):
        try:
            return safe_extract(driver_ref[0], target_url, parent_url, page_type)
        except (InvalidSessionIdException, WebDriverException) as e:
            if is_session_error(str(e)) and attempt == 0:
                print(" Session died — restarting driver...")
                try:
                    driver_ref[0].quit()
                except Exception:
                    pass
                time.sleep(5)
                driver_ref[0] = create_driver()
                print("Driver restarted, retrying...")
            else:
                # Second attempt failed, give up 
                row_data = {col: 'Not present' for col in csv_headers}
                row_data.update({'Parent_URL': parent_url, 'Page_Type': page_type,
                                 'URL': target_url, 'Status': 'Session crashed'})
                return row_data, None



# MAIN LOOP

# Wrap driver in list, helpers can swap by reference
driver_ref = [create_driver()]

login_pattern    = re.compile(r'(login|log-?in|sign-?in|signin|auth|account|session|srf)', re.IGNORECASE)
register_pattern = re.compile(r'(register|sign-?up|signup|join|create[-_]?account|reg(?:/|\.php)|newaccount)', re.IGNORECASE)

with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file:
    """
    Main crawling loop:
        - Iterates over each site in sites list.
        - For each, checks reachability, extracts main page data, and looks for login/register links.
        - Scheduled restarts every specified sites and on session related errors.
        - Writes results to results file with columns for security headers, iframe stats, and status messages.
    """
    writer = csv.DictWriter(file, fieldnames=csv_headers)
    writer.writeheader()

    consecutive_timeouts = 0

    for site_index, raw_url in enumerate(tqdm(SITES, desc="Crawling", unit="site")):

        # sheduled restart
        if site_index > 0 and site_index % RESTART_EVERY == 0:
            print(f"\n    Scheduled restart at site {site_index} to free memory...")
            try:
                driver_ref[0].quit()
            except Exception:
                pass
            time.sleep(5)
            driver_ref[0] = create_driver()
            print("Driver restarted.")

        # sanitize 
        url = sanitize_url(raw_url)
        if not url:
            print(f"    Skipping malformed URL: {raw_url}")
            continue

        print(f"    [{site_index + 1}] {url}")

        # check links
        if not is_site_reachable(url):
            print(f"    Skipping unreachable: {url}")
            unreachable_row = {col: 'Not present' for col in csv_headers}
            unreachable_row.update({'Parent_URL': url, 'Page_Type': 'Main',
                                    'URL': url, 'Status': 'Unreachable'})
            writer.writerow(unreachable_row)
            file.flush()
            continue

        time.sleep(WAIT_TIME)

        # Main page
        main_row, soup = call_with_session_recovery(driver_ref, url, url, 'Main')
        writer.writerow(main_row)
        file.flush()

        # check for timeouts
        if is_timeout_or_crash(main_row['Status']):
            consecutive_timeouts += 1
            print(f"    Consecutive timeouts/crashes: {consecutive_timeouts}/{MAX_CONSECUTIVE_TIMEOUTS}")
            if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                print("    Too many in a row :(    restarting browser")
                try:
                    driver_ref[0].quit()
                except Exception:
                    pass
                time.sleep(5)
                driver_ref[0] = create_driver()
                consecutive_timeouts = 0
                print("    Browser restarted.")
        else:
            consecutive_timeouts = 0

        # sub pages
        if not soup:
            continue

        login_url = register_url = None
        current_domain = urlparse(url).netloc

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)
            parsed_full = urlparse(full_url)

            if parsed_full.netloc == current_domain:
                if not login_url and login_pattern.search(href):
                    login_url = full_url
                if not register_url and register_pattern.search(href):
                    register_url = full_url

            if login_url and register_url:
                break

        if login_url:
            login_row, _ = call_with_session_recovery(driver_ref, login_url, url, 'Login')
            writer.writerow(login_row)
            file.flush()
        else:
            print("    No login link detected.")

        if register_url:
            reg_row, _ = call_with_session_recovery(driver_ref, register_url, url, 'Register')
            writer.writerow(reg_row)
            file.flush()
        else:
            print("    No registration link detected.")

try:
    driver_ref[0].quit()
except Exception:
    pass

print(f"\nDone :)  Results saved to: {OUTPUT_FILE}")
elapsed = time.time() - start_time
mins, secs = divmod(int(elapsed), 60)
print(f"Total time: {mins}m {secs}s")