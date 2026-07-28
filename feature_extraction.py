import socket, ssl
import tldextract
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime

def url_features(url):
    parsed = urlparse(url)
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        1 if parsed.scheme == "https" else 0,
        1 if "login" in url.lower() else 0
    ]

def whois_features(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days if creation else 0
        return [age]
    except:
        return [0]

def dns_features(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [1, len(result)]
    except:
        return [0, 0]

def ssl_features(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        valid_days = (expiry - datetime.now()).days
        return [1, valid_days]
    except:
        return [0, 0]

def extract_all_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    return (
        url_features(url)
        + whois_features(domain)
        + dns_features(domain)
        + ssl_features(domain)
    )