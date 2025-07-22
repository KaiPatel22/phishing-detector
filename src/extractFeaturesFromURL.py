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

def extractLongURL(url):
    lengthOfURL = len(url)
    if lengthOfURL < 54:
        return 1
    elif (lengthOfURL >= 54 and lengthOfURL <= 75):
        return 0
    else:
        return -1

def extractShortURL(url):
    shortenedDomain = ["tinyurl.com", "bit.ly", "goo.gl", "t.co", "is.gd", "ow.ly", "buff.ly", "adf.ly"]
    try:
        parsedURL = urlparse(url)
        domain = parsedURL.hostname
        if domain in shortenedDomain:
            return -1 
        else:
            return 1 
    except:
        logging.exception(f"Failed to parse URL for short URL extraction: {url}")
        return "Unable to extract short URL"

def extractSymbolAt(url):
    if url.count("@") > 0:
        return -1
    else:
        return 1

def extractRedirecting(url):
    if url.count("//") > 1:
        lastSlashIndex = url.rfind("//")
        if lastSlashIndex > 7:
            return -1
        else:
            return 1
    else:
        return 1

def extractSymbolDash(url):
    parsedURL = urlparse(url)
    domain = parsedURL.netloc
    if domain.count("-") > 0:
        return -1
    else:
        return 1

