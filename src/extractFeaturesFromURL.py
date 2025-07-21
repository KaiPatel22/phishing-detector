import logging
from urllib.parse import urlparse
import sys
from IPy import IP

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(message)s'
)

def extractUsingIP(url): # Currently doesn't handle URLs where the IP address has been converted to hexadecimal
    domain = getDomain(url)
    try:
        ip = IP(domain)
        return -1
    except: # Will throw an exception if the domain is not an IP address
        return 1

def getDomain(url):
    try:
        parsedURL = urlparse(url)
        domain = parsedURL.netloc
    except:
        logging.exception(f"Failed to parse URL: {url}")
        sys.exit(1)
    if (domain == ""):
        logging.error(f"Domain extraction failed for URL: {url}")
    return domain

print(extractUsingIP("http://125.98.3.123/fake.html"))