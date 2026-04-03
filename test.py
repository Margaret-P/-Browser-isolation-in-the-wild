import csv
import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
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
SITES = [] # take first 5000 from top-1m.csv

with open('top-1m.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)  # skip header
    for i, row in enumerate(reader):
        if i >= 5000:
            break
        SITES.append(row[1])  # assuming URL is in the second column



OUTPUT_FILE = 'results.csv'
HEADLESS = False # controlls if browser shown or not
WAIT_TIME = 10 # 10 seconds ideal

# Headers to track in columns
HEADERS = [
    'cross-origin-opener-policy',   # COOP     window/tab isolation
    'cross-origin-embedder-policy', # COEP     embedded resource requirements
    'cross-origin-resource-policy', # CORP     who can load this resource
    'content-security-policy',      # CSP      overall content security
    'x-frame-options',              # XFO      clickjacking  
]

# STEP 1: SETUP BROWSER 
print("Setting up browser")
options = Options()  # create options
if HEADLESS:
    options.add_argument('--headless=new') # manage headless mode

options.set_capability('goog:loggingPrefs', {'performance': 'ALL'}) # launch chrome with Selenium and logging
options.add_experimental_option('perfLoggingPrefs', {'enableNetwork': True})

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=options) # create driver instance


# STEP 2: PREPARE CSV 
csv_headers = [
    'Parent_URL', 'Page_Type', 'URL', 
    'COOP', 'COEP', 'CORP', 'CSP', 'XFO', 
    'Iframe_Count', 'Cross_Origin_Iframes', 'Sandboxed_Iframes',
    'Status'
]

def extract_page_data(driver, target_url, parent_url, page_type): # visits URL, waits, extracts, returns row data
    print(f"[{page_type}], {target_url}")
    row_data = {col: 'Not present' for col in csv_headers}
    row_data['Parent_URL'] = parent_url
    row_data['Page_Type'] = page_type
    row_data['URL'] = target_url
    row_data['Iframe_Count'] = str(0)
    row_data['Cross_Origin_Iframes'] = str(0)
    row_data['Sandboxed_Iframes'] = str(0)
    
    try:
        # Clear previous performance logs
        driver.get_log('performance')
        driver.get(target_url)
        
        # get network headers
        logs = driver.get_log('performance')
        resp_headers = {} 
    
        for log in logs: # iterate logs for network responses
            message = json.loads(log['message'])
            method = message.get('message', {}).get('method', '')
            
            if method == 'Network.responseReceived':
                params = message.get('message', {}).get('params', {})
                resp_url = params.get('response', {}).get('url', '')
                
                # Check if log entry is for the requested page
                if target_url.strip('/') in resp_url:
                    # Convert all headers to lowercase 
                    raw_headers = params.get('response', {}).get('headers', {})
                    resp_headers = {k.lower(): v for k, v in raw_headers.items()}
                    break
        
        # Map headers to columns
        row_data['COOP'] = resp_headers.get('cross-origin-opener-policy', 'Not present') 
        row_data['COEP'] = resp_headers.get('cross-origin-embedder-policy', 'Not present')
        row_data['CORP'] = resp_headers.get('cross-origin-resource-policy', 'Not present')
        row_data['CSP'] = resp_headers.get('content-security-policy', 'Not present')
        row_data['XFO'] = resp_headers.get('x-frame-options', 'Not present')

        # get Iframes
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        iframes = soup.find_all('iframe')
        row_data['Iframe_Count'] = str(len(iframes)) 
        
        current_domain = urlparse(target_url).netloc
        co_count = 0 
        sb_count = 0
        
        for ifr in iframes: # iterate iframes
            src = str(ifr.get('src', ''))
            
            # Cross-origin check
            if (src.startswith('http')) and (current_domain not in src):
                co_count += 1
            
            # Sandbox check
            if ifr.has_attr('sandbox'):
                sb_count += 1

        row_data['Cross_Origin_Iframes'] = str(co_count) 
        row_data['Sandboxed_Iframes'] = str(sb_count)
        row_data['Status'] = 'Success'

        return row_data, soup

    except Exception as e: 
        print(f"Error on {target_url}: {e}")
        row_data['Status'] = f"Error: {str(e)[:20]}"
        return row_data, None

# STEP 3: EXECUTE

def sanitize_url(domain):
    domain = domain.strip()

    # If domain already has scheme, keep it
    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = "https://" + domain

    # Validate URL structure
    parsed = urlparse(url)
    if not parsed.netloc:
        return None

    # Remove illegal characters
    if re.search(r"[\s<>\"{}|\\^`]", url):
        return None

    return url


with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.DictWriter(file, fieldnames=csv_headers)
    writer.writeheader()

    for url in tqdm(SITES, desc="Running", unit="site"):
    #santize URL and skip if invalid
        url = sanitize_url(url)
        if not url:
            print(f"Skipping invalid URL: {url}")
            continue
    
    # for url in SITES:
        print(f"\nDoing {url}")
        time.sleep(WAIT_TIME)
        
        #Extract Main Page
        main_row, soup = extract_page_data(driver, url, url, 'Main')
        writer.writerow(main_row)
        
        # Find Login/Registration Links
        if soup:
            login_url = None
            register_url = None
            current_domain = urlparse(url).netloc
            
            # Regex for login/register keywords
            # both login and register pages detected for github and facebooks, neither for youtube or wikipedia. (example.com doesn't have)
            login_pattern = re.compile(r'(login|log-?in|sign-?in|auth|account)', re.IGNORECASE)
            register_pattern = re.compile(r'(register|sign-?up|join|create[-_]?account|reg(?:/|\.php))', re.IGNORECASE)

            for a_tag in soup.find_all('a', href=True): # iterate all links
                
                href = a_tag['href']
                full_url = urljoin(url, href) # Converts relative URLs to absolute
                parsed_full = urlparse(full_url)
                
                # Check if is internal link
                if parsed_full.netloc == current_domain:
                    # Look for login
                    # if not login_url and any(pattern.search(href) for pattern in login_pattern):  # uncomment for list of patterns
                    if not login_url and login_pattern.search(href):
                        login_url = full_url
                    # Look for register
                    # if not register_url and any(pattern.search(href) for pattern in register_pattern): # uncomment for list of patterns
                    if not register_url and register_pattern.search(href):
                        register_url = full_url
                
                # Break early if found both
                if login_url and register_url:
                    break
            
            # Visit, Extract Sub-pages
            if login_url:
                login_row, _ = extract_page_data(driver, login_url, url, 'Login')
                writer.writerow(login_row)
            else:
                print("No login link detected.")
                
            if register_url:
                register_row, _ = extract_page_data(driver, register_url, url, 'Register')
                writer.writerow(register_row)
            else:
                print("No registration link detected.")

driver.quit() 
print(f"\nDone :)  Results saved to: {OUTPUT_FILE}")

elapsed = time.time() - start_time
mins, secs = divmod(int(elapsed), 60)
print(f"Total time: {mins}m {secs}s")