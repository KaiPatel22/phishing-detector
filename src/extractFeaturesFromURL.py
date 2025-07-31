import logging
from urllib.parse import urlparse
import sys
from IPy import IP
import ssl
import socket
from datetime import datetime
from bs4 import BeautifulSoup
import requests

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

def extractSubDomains(url):
    ccTLDs = [ # Used chatGPT to create an array of country code top level domains
    ".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".ao", ".aq", ".ar", ".as", ".at", ".au", ".aw",
    ".ax", ".az", ".ba", ".bb", ".bd", ".be", ".bf", ".bg", ".bh", ".bi", ".bj", ".bm", ".bn", ".bo", ".bq",
    ".br", ".bs", ".bt", ".bv", ".bw", ".by", ".bz", ".ca", ".cc", ".cd", ".cf", ".cg", ".ch", ".ci", ".ck",
    ".cl", ".cm", ".cn", ".co", ".cr", ".cu", ".cv", ".cw", ".cx", ".cy", ".cz", ".de", ".dj", ".dk", ".dm",
    ".do", ".dz", ".ec", ".ee", ".eg", ".eh", ".er", ".es", ".et", ".eu", ".fi", ".fj", ".fk", ".fm", ".fo",
    ".fr", ".ga", ".gb", ".gd", ".ge", ".gf", ".gg", ".gh", ".gi", ".gl", ".gm", ".gn", ".gp", ".gq", ".gr",
    ".gt", ".gu", ".gw", ".gy", ".hk", ".hm", ".hn", ".hr", ".ht", ".hu", ".id", ".ie", ".il", ".im", ".in",
    ".io", ".iq", ".ir", ".is", ".it", ".je", ".jm", ".jo", ".jp", ".ke", ".kg", ".kh", ".ki", ".km", ".kn",
    ".kp", ".kr", ".kw", ".ky", ".kz", ".la", ".lb", ".lc", ".li", ".lk", ".lr", ".ls", ".lt", ".lu", ".lv",
    ".ly", ".ma", ".mc", ".md", ".me", ".mf", ".mg", ".mh", ".mk", ".ml", ".mm", ".mn", ".mo", ".mp", ".mq",
    ".mr", ".ms", ".mt", ".mu", ".mv", ".mw", ".mx", ".my", ".mz", ".na", ".nc", ".ne", ".nf", ".ng", ".ni",
    ".nl", ".no", ".np", ".nr", ".nu", ".nz", ".om", ".pa", ".pe", ".pf", ".pg", ".ph", ".pk", ".pl", ".pm",
    ".pn", ".pr", ".ps", ".pt", ".pw", ".py", ".qa", ".re", ".ro", ".rs", ".ru", ".rw", ".sa", ".sb", ".sc",
    ".sd", ".se", ".sg", ".sh", ".si", ".sj", ".sk", ".sl", ".sm", ".sn", ".so", ".sr", ".ss", ".st", ".sv",
    ".sx", ".sy", ".sz", ".tc", ".td", ".tf", ".tg", ".th", ".tj", ".tk", ".tl", ".tm", ".tn", ".to", ".tr",
    ".tt", ".tv", ".tz", ".ua", ".ug", ".uk", ".us", ".uy", ".uz", ".va", ".vc", ".ve", ".vg", ".vi", ".vn",
    ".vu", ".wf", ".ws", ".ye", ".yt", ".za", ".zm", ".zw"
    ]

    parsedURL = urlparse(url)
    domain = parsedURL.netloc

    if domain.startswith("www."):
        trimmedDomain = domain.replace("www.","")

    if trimmedDomain.count(".") > 0:
        indexOfPeriod = trimmedDomain.rfind(".")
        lengthOfDomain = len(trimmedDomain)
        finalPeriodInDomain = trimmedDomain[indexOfPeriod:lengthOfDomain]
        if finalPeriodInDomain in ccTLDs:
            trimmedDomain = trimmedDomain[:indexOfPeriod]

    if trimmedDomain.count(".") > 2:
        return -1
    elif trimmedDomain.count(".") > 1:
        return 0
    else:
        return 1

def extractHTTPS(url): # THIS METHOD MIGHT NOT BE THE BEST INDICATOR IF A URL IS PHISHING (MARKS A LOT OF URLS AS SUSPICIOUS)
    trustedIssuers = [
        "DigiCert Inc", "Sectigo Limited", "Let's Encrypt", "GlobalSign",
        "Entrust, Inc.", "Amazon Trust Services LLC", "Google Trust Services",
        "GoDaddy.com, Inc.", "Buypass AS", "Actalis S.p.A.",
        "Certum", "SSL.com", "Izenpe S.A.",
        "QuoVadis Limited", "TWCA", "SwissSign AG", "Trustwave Holdings, Inc."
    ]

    parsedURL = urlparse(url)
    if parsedURL.scheme == "http":
        return -1
    else:
        try:
            hostname = parsedURL.hostname
            context = ssl.create_default_context()
            cert = context.wrap_socket(socket.create_connection((hostname, 443)), server_hostname=hostname).getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            issuerName = issuer['organizationName'] if 'organizationName' in issuer else issuer['commonName']
            isTrustedIssuer = issuerName in trustedIssuers
            if not(isTrustedIssuer):
                return 0 
            else:
                becomesValid = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                certificateAge = (datetime.now() - becomesValid).days / 365.0
                if certificateAge >= 1.0:
                    return 1
                else:
                    return 0
        except:
            logging.exception(f"Failed to extract SSL certificate for URL: {url}")
            sys.exit(1)

def extractDomainRegLen(url): # AGAIN DON'T KNOW HOW EFECTIVE THIS FEATURE IS AS REPORTS LOTS OF URLs AS SUSPICIOUS
    try:
        parsedURL = urlparse(url)
        hostname = parsedURL.hostname
        context = ssl.create_default_context()
        cert = context.wrap_socket(socket.create_connection((hostname, 443)), server_hostname=hostname).getpeercert()
        expiryDate = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        remainingValidity = (expiryDate - datetime.now()).days / 365.0
        if remainingValidity <= 1.0:
            return -1 
        else:
            return 1
    except:
        logging.exception(f"Failed to extract domain registration length for URL: {url}")
        sys.exit(1)

def extractHTTPSDomainURL(url):
    parsedURL = urlparse(url)
    domain = parsedURL.netloc
    if parsedURL.scheme == "http" or domain.count("https") > 0:
        return -1
    else:
        return 1
    
def extractRequestURL(url):
    try:
        parsedURL = urlparse(url)
        domain = parsedURL.netloc
        reponse = requests.get(url, timeout=10)
        urlContent = BeautifulSoup(reponse.content, 'html.parser')
        objects = []
        for tag in ["img", "video", "audio", "iframe", "embed"]:
            for element in urlContent.find_all(tag):
                src = element.get("src")
                objects.append(src)
            
        externalObjectCount = 0
        for objectURL in objects:
            imageURL = urlparse(objectURL)
            imageDomain = imageURL.netloc
            if imageDomain and imageDomain != domain:
                externalObjectCount += 1
        
        externalPercentage = (externalObjectCount / len(objects)) * 100
        if externalPercentage < 22:
            return 1
        elif externalPercentage >= 22 and externalPercentage <= 61:
            return 0 
        else:
            return -1
    except:
        logging.exception(f"Failed to make request to URL: {url}")
        sys.exit(1)

print(extractRequestURL("https://apple.com"))