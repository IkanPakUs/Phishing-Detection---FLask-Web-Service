import urllib.request as urllib2
import dns.resolver
import tldextract
import ipaddress
import requests
import socket
import whois
import ssl
import time
import re
import os

import requests

from cymruwhois import Client
from cryptography import x509
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime, date, timezone
from bs4 import BeautifulSoup

class Extract:
    url = ''

    def __init__(self, url) -> None:
        self.url = urlparse(url)

    def extractFeature(self):
        based_url = self.extractBasedOnUrl()
        based_domain = self.extractBasedOnDomain()
        based_directory = self.extractBasedOnDirectory()
        based_file = self.extractBasedOnFile()
        based_parameter = self.extractBasedOnParameter()
        based_external_service = self.extractBasedOnExternalService()

        feature = {}

        feature.update(based_url)
        feature.update(based_domain)
        feature.update(based_directory)
        feature.update(based_file)
        feature.update(based_parameter)
        feature.update(based_external_service)

        return feature

    def extractBasedOnUrl(self):
        full_url = self.url.geturl()
        full_url = full_url.replace("%s://" % self.url.scheme, '', 1)

        extracted = tldextract.extract(self.url.netloc)

        qty_tld = {'qty_tld_url': len(extracted.suffix.split('.') if extracted.suffix != '' else [])}
        qty_url = {'length_url': len(full_url)}
        
        url_symbol = {
            'qty_dot_url': len(re.findall(r'\.', full_url)),
            'qty_hyphen_url': len(re.findall(r'\-', full_url)),
            'qty_underline_url': len(re.findall(r'\_', full_url)),
            'qty_slash_url': len(re.findall(r'\/', full_url)),
            'qty_at_url': len(re.findall(r'\@', full_url)),
            'qty_and_url': len(re.findall(r'\&', full_url)),
            'qty_comma_url': len(re.findall(r'\,', full_url)),
            'qty_plus_url': len(re.findall(r'\+', full_url)),
            'qty_percent_url': len(re.findall(r'\%', full_url)),
        }

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_tld)
        url_feature.update(qty_url)

        return url_feature

    def extractBasedOnDomain(self):
        domain = self.url.netloc
        
        qty_vowel = {'qty_vowels_domain': len(re.findall(r'[aeiouAEIOU]', domain))}
        domain_length = {'domain_length': len(domain)}
        ip_in_domain = {'domain_in_ip': 0}

        try:
            ipaddress.ip_address(domain)
            ip_in_domain['domain_in_ip'] = 1
        except ValueError:
            ip_in_domain['domain_in_ip'] = 0

        url_symbol = {
            'qty_dot_domain': len(re.findall(r'\.', domain)),
            'qty_hyphen_domain': len(re.findall(r'\-', domain)),
        }
    
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_vowel)
        url_feature.update(domain_length)
        url_feature.update(ip_in_domain)

        return url_feature

    def extractBasedOnDirectory(self):
        path = self.url.path
        dir_length = len(path) if len(path) > 0 else -1

        directory_length = {'directory_length': dir_length}
        
        url_symbol = {
            'qty_dot_directory': len(re.findall(r'\.', path)) if len(path) > 0 else -1,
            'qty_hyphen_directory': len(re.findall(r'\-', path)) if len(path) > 0 else -1,
            'qty_underline_directory': len(re.findall(r'\_', path)) if len(path) > 0 else -1,
            'qty_slash_directory': len(re.findall(r'\/', path)) if len(path) > 0 else -1,
            'qty_equal_directory': len(re.findall(r'\=', path)) if len(path) > 0 else -1,
            'qty_at_directory': len(re.findall(r'\@', path)) if len(path) > 0 else -1,
            'qty_asterisk_directory': len(re.findall(r'\*', path)) if len(path) > 0 else -1,
            'qty_percent_directory': len(re.findall(r'\%', path)) if len(path) > 0 else -1,
        }

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(directory_length)

        return url_feature

    def extractBasedOnFile(self):
        path = self.url.path
        head, tail = os.path.split(path)

        file_length = {'file_length': len(tail) if len(path) > 0 else -1}
        
        url_symbol = {
            'qty_dot_file': len(re.findall(r'\.', tail)) if len(path) > 0 else -1,
            'qty_hyphen_file': len(re.findall(r'\-', tail)) if len(path) > 0 else -1,
            'qty_underline_file': len(re.findall(r'\_', tail)) if len(path) > 0 else -1,
            'qty_percent_file': len(re.findall(r'\%', tail)) if len(path) > 0 else -1,
        }

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(file_length)

        return url_feature

    def extractBasedOnParameter(self):
        params = self.url.query

        par_length = len(params) if len(params) > 0 else -1

        params_length = {'params_length': len(params) if par_length != -1 else -1}
        tld_presents = {'tld_present_params': 1 if bool(re.search(fr'\b{re.escape(self.url.netloc)}\b', params, re.IGNORECASE)) else 0 if par_length != -1 else -1}
        qty_params = {'qty_params': len(parse_qs(self.url.query)) if par_length != -1 else -1}

        url_feature = {}
        url_feature.update(params_length)
        url_feature.update(tld_presents)
        url_feature.update(qty_params)

        return url_feature

    def extractBasedOnExternalService(self):
        url = self.url.geturl()
        extracted = tldextract.extract(self.url.netloc)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"}

        try:
            dns_start = time.time()
            socket.gethostbyname(self.url.netloc)
            dns_end = time.time()

            time_response = (dns_end - dns_start)
        except Exception:
            time_response = -1.000000

        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_count = 1 if sum('v=spf' in record.strings for record in spf_records) >= 1 else 0
        except Exception:
            spf_count = -1

        try:
            whois_info = whois.whois(domain)
            date_now = date.today()
            domain_creation = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
            domain_expired = whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, list) else whois_info.expiration_date

            if (domain_creation is not None):
                domain_activation = abs((domain_creation.date() - date_now).days)
            else:
                domain_activation = -1

            if (domain_expired is not None):
                domain_expiration = abs((date_now - domain_expired.date()).days)
            else:
                domain_expiration = -1
        except Exception:
            domain_expiration = -1
            domain_activation = -1

        try:
            ip_answers = dns.resolver.resolve(domain, 'A')
            resolved_ips = len([answer.address for answer in ip_answers])
        except Exception:
            resolved_ips = -1

        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            resolved_ns = len(ns_answers)
        except Exception:
            resolved_ns = 0

        try:
            mx_servers = len(dns.resolver.resolve(domain, 'MX'))
        except Exception:
            mx_servers = 0

        try:
            cert = ssl.get_server_certificate((self.url.netloc, 443))
            cert_data = x509.load_pem_x509_certificate(str.encode(cert))
            expiration_date = cert_data.not_valid_after_utc
            days_left = (expiration_date - datetime.now(timezone.utc)).days
            tls_ssl = 1 if days_left > 0 else 0
        except Exception as e:
            tls_ssl = 0

        try:
            response = requests.get(url, headers=headers, timeout=60)
            redirect = len(response.history)
            url_short = 1 if len(url) < len(response.url) and self.url.netloc != urlparse(response.url).netloc else 0
        except Exception:
            redirect = -1
            url_short = 0

        return {
            'time_response': time_response,
            'domain_spf': spf_count,
            'time_domain_activation': domain_activation,
            'time_domain_expiration': domain_expiration,
            'qty_ip_resolved': resolved_ips,
            'qty_nameservers': resolved_ns,
            'qty_mx_servers': mx_servers,
            'tls_ssl_certificate': tls_ssl,
            'qty_redirects': redirect,
            'url_shortened': url_short,
        }