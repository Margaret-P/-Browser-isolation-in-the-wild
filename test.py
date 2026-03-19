import csv
import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# --- CONFIGURATION ---
SITES = [
    'https://example.com',
    'https://github.com',
    'https://wikipedia.org',
    'https://youtube.com',
    'https://facebook.com',
]

OUTPUT_FILE = 'results.csv'
HEADLESS = True # controlls if browser shown or not

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
    'URL', 
    'COOP', 'COEP', 'CORP', 'CSP', 'XFO', 
    'Iframe_Count', 'Cross_Origin_Iframes', 'Sandboxed_Iframes',
    'Status'
]

with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file: # csv file with the columns as the headers
    writer = csv.DictWriter(file, fieldnames=csv_headers)
    writer.writeheader()

        # STEP 3: ITERATE THROUGH SITES 
    for url in SITES:
        print(f"Analyzing: {url}")
        row_data = {col: 'Not present' for col in csv_headers}  # start row with 'Not Present' for defined headers
        row_data['URL'] = url 
        row_data['Iframe_Count'] = 0
        row_data['Cross_Origin_Iframes'] = 0
        row_data['Sandboxed_Iframes'] = 0
        
        try:
            driver.get(url)
            time.sleep(10) # Wait a bit for loading (at least 5 seconds?)
            
            # 1. get network headers
            logs = driver.get_log('performance')
            resp_headers = {} 
            
            for log in logs: # find log with the response headers for the main page request
                message = json.loads(log['message'])
                method = message.get('message', {}).get('method', '')
                
                if method == 'Network.responseReceived': # check if log entry is for main page response
                    params = message.get('message', {}).get('params', {})
                    if url.strip('/') in params.get('response', {}).get('url', ''):
                        resp_headers = params.get('response', {}).get('headers', {})
                        break
            
            # Map headers to  columns
            row_data['COOP'] = resp_headers.get('cross-origin-opener-policy', 'Not present') 
            row_data['COEP'] = resp_headers.get('cross-origin-embedder-policy', 'Not present')
            row_data['CORP'] = resp_headers.get('cross-origin-resource-policy', 'Not present')
            
            if 'content-security-policy' in resp_headers: # check if CSP peresnt
                # row_data['CSP'] = resp_headers.get('content-security-policy', 'Present')   # inserts actual value  (kinda long)
                row_data['CSP'] = 'Present'
            else:
                row_data['CSP'] = 'Not present'

            row_data['XFO'] = resp_headers.get('x-frame-options', 'Not present') # check if XFO present

            # 2. get Iframes
            soup = BeautifulSoup(driver.page_source, 'html.parser')  # find iframes and count
            iframes = soup.find_all('iframe')
            row_data['Iframe_Count'] = len(iframes) 
            

            current_domain = urlparse(url).netloc # domain for cross origin check, start counters
            co_count = 0 
            sb_count = 0
            
            for ifr in iframes:
                src = ifr.get('src', '') # get src of ifram if not then empty string
                
                # Cross-origin check
                if (src.startswith('http')) and (current_domain not in src): # if src absolute url + domain not in src then cross origin
                    co_count += 1
                
                # Sandbox check
                if ifr.has_attr('sandbox'): # if sandbox present then sandboxed
                    sb_count += 1

            row_data['Cross_Origin_Iframes'] = co_count 
            row_data['Sandboxed_Iframes'] = sb_count
            row_data['Status'] = 'Success'

        except Exception as e: 
            print(f"  Error on {url}: {e}")
            row_data['Status'] = f"Error: {str(e)[:20]}"

        # Write the row  to csv
        writer.writerow(row_data)

driver.quit() 
print(f"\nDone :)  Results saved to: {OUTPUT_FILE}")