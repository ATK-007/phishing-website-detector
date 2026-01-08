import re
from urllib.parse import urlparse

def has_ip_address(url):
    ip_pattern = re.compile(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}'
    )
    return bool(ip_pattern.search(url))

def is_long_url(url):
    return len(url) > 75

def no_https(url):
    return not url.startswith("https")

def suspicious_words(url):
    words = ['login', 'verify', 'update', 'secure', 'account', 'bank']
    return any(word in url.lower() for word in words)

def many_subdomains(url):
    domain = urlparse(url).netloc
    return domain.count('.') > 3

def detect_phishing(url):
    score = 0
    if has_ip_address(url): score += 1
    if is_long_url(url): score += 1
    if no_https(url): score += 1
    if suspicious_words(url): score += 1
    if many_subdomains(url): score += 1

    return "⚠️ Phishing Website Detected" if score >= 3 else "✅ Legitimate Website"

if __name__ == "__main__":
    url = input("Enter URL: ")
    print(detect_phishing(url))
