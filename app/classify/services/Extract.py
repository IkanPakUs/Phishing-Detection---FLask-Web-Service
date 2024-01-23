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
from urllib.parse import urlparse, parse_qs
from datetime import datetime, date

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
        
        url_symbol = self.extractSymbol(full_url, '_url')
        qty_tld = {'qty_tld_url': len(tldextract.extract(full_url).suffix)}
        qty_url = {'length_url': len(full_url)}
        is_has_email = {'email_in_url': 1 if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', full_url) is not None else 0}
        
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_tld)
        url_feature.update(qty_url)
        url_feature.update(is_has_email)
        
        return url_feature
    
    def extractBasedOnDomain(self):
        domain = self.url.netloc
        
        url_symbol = self.extractSymbol(domain, '_domain')
        qty_vowel = {'qty_vowels_domain': len(re.findall(r'[aeiouAEIOU]', domain))}
        domain_length = {'domain_length': len(domain)}
        ip_in_domain = {'domain_in_ip': 0}

        try:
            ipaddress.ip_address(domain)
            ip_in_domain['domain_in_ip'] = 1
        except ValueError:
            ip_in_domain['domain_in_ip'] = 0
            
        server_client_domain = {'server_client_domain': 1 if bool(re.compile(r'\bserver\b', re.IGNORECASE).search(domain) or re.compile(r'\bclient\b', re.IGNORECASE).search(domain)) else 0}
        
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_vowel)
        url_feature.update(domain_length)
        url_feature.update(ip_in_domain)
        url_feature.update(server_client_domain)
        
        return url_feature
    
    def extractBasedOnDirectory(self):
        path = os.path.dirname(self.url.path)
        
        url_symbol = self.extractSymbol(path, '_directory')
        directory_length = {'directory_length': len(path)}
        
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(directory_length)
        
        return url_feature

    def extractBasedOnFile(self):
        file = os.path.basename(self.url.path)
        
        url_symbol = self.extractSymbol(file, '_file')
        file_length = {'file_length': len(file)}
        
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(file_length)
        
        return url_feature
        
    def extractBasedOnParameter(self):
        params = self.url.query
        
        url_symbol = self.extractSymbol(params, '_params')
        params_length = {'params_length': len(params)}
        tld_presents = {'tld_present_params': 1 if re.compile(r'\.([a-zA-Z]{2,})$').search(params) is not None else 0}
        qty_params = {'qty_params': len(parse_qs(self.url.query))}
        
        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(params_length)
        url_feature.update(tld_presents)
        url_feature.update(qty_params)        

        return url_feature

    def extractBasedOnExternalService(self):
        url = self.url.geturl()

        dns_start = time.time()
        socket.gethostbyname(self.url.netloc)
        dns_end = time.time()
        
        try:
            spf_records = dns.resolver.resolve(self.url.netloc, 'TXT')
            spf_count = 1 if sum('v=spf' in record.strings for record in spf_records) >= 1 else 0
        except dns.resolver.NoAnswer:
            spf_count = -1
        
        response = requests.get(f"https://ipinfo.io/{url}/json")
        data = response.json()
        asn = data.get('asn', 'N/A')
        
        whois_info = whois.whois(url)

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
        
        resolved_ips = -1
        resolved_ns4 = -1
        
        try:
            ip_answers = dns.resolver.resolve(self.url.netloc, 'A')
            resolved_ips = len([answer.address for answer in ip_answers])

            ns_answers = dns.resolver.resolve(self.url.netloc, 'NS')
            resolved_ns4 = len([answer.target.to_text() for answer in ns_answers if 'ns4' in answer.target.to_text().lower()])
            
        except dns.resolver.NXDOMAIN:
            pass
        except dns.exception.DNSException as e:
            pass
        except dns.resolver.NoAnswer:
            pass
            
        try:
            mx_servers = len(dns.resolver.resolve(self.url.netloc, 'MX'))
        except dns.resolver.NoAnswer:
            mx_servers = -1
        
        try:
            answers = dns.resolver.resolve(self.url.netloc, 'A')
            ttl = answers.rrset.ttl
        except dns.resolver.NoAnswer:
            ttl = -1
        except dns.resolver.NXDOMAIN:
            ttl = -1
            
        try:
            cert = ssl.get_server_certificate((url, 443))
            x509 = ssl.load_certificate(ssl.PEM_cert_to_DER_cert(cert))
            expiration_date = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
            days_left = (expiration_date - datetime.datetime.now()).days
            tls_ssl = days_left > 0
        except Exception as e:
            tls_ssl = -1
        
        response = requests.get(url)
        redirect = len(response.history)
        
        final_url = requests.head(url, allow_redirects=True).url
        
        if len(url) > len(final_url):
            url_short = 1
        else:
            url_short = 0
            
        return {
            'time_response': ((dns_end - dns_start) * 1000),
            'domain_spf': spf_count,
            'asn_ip': len(asn),
            'time_domain_activation': domain_activation,
            'time_domain_expiration': domain_expiration,
            'qty_ip_resolved': resolved_ips,
            'qty_nameservers': resolved_ns4,
            'qty_mx_servers': mx_servers,
            'ttl_hostname': ttl,
            'tls_ssl_certificate': tls_ssl,
            'qty_redirects': redirect,
            'url_google_index': -1,
            'domain_google_index': -1,
            'url_shortened': url_short,
        }
    
    def extractSymbol(self, url, prefix):
        qty_dot = len(re.findall(r'\.', url))
        qty_hyphen = len(re.findall(r'\-', url))
        qty_underline = len(re.findall(r'\_', url))
        qty_slash = len(re.findall(r'\/', url))
        qty_questionmark = len(re.findall(r'\?', url))
        qty_equal = len(re.findall(r'\=', url))
        qty_at = len(re.findall(r'\@', url))
        qty_and = len(re.findall(r'\&', url))
        qty_exclamation = len(re.findall(r'\!', url))
        qty_space = len(re.findall(r'\ ', url))
        qty_tilde = len(re.findall(r'\~', url))
        qty_comma = len(re.findall(r'\,', url))
        qty_plus = len(re.findall(r'\+', url))
        qty_asterisk = len(re.findall(r'\*', url))
        qty_hashtag = len(re.findall(r'\#', url))
        qty_dollar = len(re.findall(r'\$', url))
        qty_percent = len(re.findall(r'\%', url))

        return {
            'qty_dot' + prefix: qty_dot,
            'qty_hyphen' + prefix: qty_hyphen,
            'qty_underline' + prefix: qty_underline,
            'qty_slash' + prefix: qty_slash,
            'qty_questionmark' + prefix: qty_questionmark,
            'qty_equal' + prefix: qty_equal,
            'qty_at' + prefix: qty_at,
            'qty_and' + prefix: qty_and,
            'qty_exclamation' + prefix: qty_exclamation,
            'qty_space' + prefix: qty_space,
            'qty_tilde' + prefix: qty_tilde,
            'qty_comma' + prefix: qty_comma,
            'qty_plus' + prefix: qty_plus,
            'qty_asterisk' + prefix: qty_asterisk,
            'qty_hashtag' + prefix: qty_hashtag,
            'qty_dollar' + prefix: qty_dollar,
            'qty_percent' + prefix: qty_percent,
        }