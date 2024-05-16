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

        url_symbol = self.extractSymbol(full_url, '_url', 0)
        qty_tld = {'qty_tld_url': len(extracted.suffix.split(
            '.') if extracted.suffix != '' else [])}
        qty_url = {'length_url': len(full_url)}
        is_has_email = {'email_in_url': 1 if re.search(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', full_url) is not None else 0}

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_tld)
        url_feature.update(qty_url)
        url_feature.update(is_has_email)

        return url_feature

    def extractBasedOnDomain(self):
        domain = self.url.netloc

        url_symbol = self.extractSymbol(domain, '_domain',  0)
        qty_vowel = {'qty_vowels_domain': len(
            re.findall(r'[aeiouAEIOU]', domain))}
        domain_length = {'domain_length': len(domain)}
        ip_in_domain = {'domain_in_ip': 0}

        try:
            ipaddress.ip_address(domain)
            ip_in_domain['domain_in_ip'] = 1
        except ValueError:
            ip_in_domain['domain_in_ip'] = 0

        server_client_domain = {'server_client_domain': 1 if bool(re.compile(r'\bserver\b', re.IGNORECASE).search(
            domain) or re.compile(r'\bclient\b', re.IGNORECASE).search(domain)) else 0}

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(qty_vowel)
        url_feature.update(domain_length)
        url_feature.update(ip_in_domain)
        url_feature.update(server_client_domain)

        return url_feature

    def extractBasedOnDirectory(self):
        path = self.url.path
        dir_length = len(path) if len(path) > 0 else -1

        directory_length = {'directory_length': dir_length}
        url_symbol = self.extractSymbol(path, '_directory', dir_length)

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(directory_length)

        return url_feature

    def extractBasedOnFile(self):
        path = self.url.path
        head, tail = os.path.split(path)

        dir_length = len(path) if len(path) > 0 else -1

        url_symbol = self.extractSymbol(tail, '_file', dir_length)
        file_length = {'file_length': len(tail) if dir_length != -1 else -1}

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(file_length)

        return url_feature

    def extractBasedOnParameter(self):
        params = self.url.query

        par_length = len(params) if len(params) > 0 else -1

        url_symbol = self.extractSymbol(params, '_params', par_length)
        params_length = {'params_length': len(
            params) if par_length != -1 else -1}
        tld_presents = {'tld_present_params': 1 if bool(re.search(
            fr'\b{re.escape(self.url.netloc)}\b', params, re.IGNORECASE)) else 0 if par_length != -1 else -1}
        qty_params = {'qty_params': len(
            parse_qs(self.url.query)) if par_length != -1 else -1}

        url_feature = {}
        url_feature.update(url_symbol)
        url_feature.update(params_length)
        url_feature.update(tld_presents)
        url_feature.update(qty_params)

        return url_feature

    def extractBasedOnExternalService(self):
        url = self.url.geturl()
        extracted = tldextract.extract(self.url.netloc)
        domain = f"{extracted.domain}.{extracted.suffix}"

        try:
            dns_start = time.time()
            socket.gethostbyname(self.url.netloc)
            dns_end = time.time()

            time_response = ((dns_end - dns_start) * 1000)
        except Exception:
            time_response = -1.000000

        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_count = 1 if sum(
                'v=spf' in record.strings for record in spf_records) >= 1 else 0
        except Exception:
            spf_count = -1

        try:
            client = Client()
            ip = socket.gethostbyname(self.url.netloc)
            lookup = client.lookup(ip)
            asn = int(lookup.asn)
        except Exception:
            asn = -1

        try:
            whois_info = whois.whois(domain)
            date_now = date.today()
            domain_creation = whois_info.creation_date[0] if isinstance(
                whois_info.creation_date, list) else whois_info.creation_date
            domain_expired = whois_info.expiration_date[0] if isinstance(
                whois_info.expiration_date, list) else whois_info.expiration_date

            if (domain_creation is not None):
                domain_activation = abs(
                    (domain_creation.date() - date_now).days)
            else:
                domain_activation = -1

            if (domain_expired is not None):
                domain_expiration = abs(
                    (date_now - domain_expired.date()).days)
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
            answers = dns.resolver.resolve(self.url.netloc, 'A')
            ttl = answers.rrset.ttl
        except Exception:
            ttl = -1

        try:
            cert = ssl.get_server_certificate((self.url.netloc, 443))
            cert_data = x509.load_pem_x509_certificate(str.encode(cert))
            expiration_date = cert_data.not_valid_after_utc
            days_left = (expiration_date - datetime.now(timezone.utc)).days
            tls_ssl = 1 if days_left > 0 else 0
        except Exception as e:
            tls_ssl = 0

        try:
            response = requests.get(url)
            redirect = len(response.history)
        except Exception:
            redirect = -1

        url_query = {'q': 'cache:info:' + url}
        domain_query = {'q': 'cache:info:' + self.url.netloc}

        url_google_index = self.getIsIndexesOnGoogle(url_query)
        domain_google_index = self.getIsIndexesOnGoogle(domain_query)

        try:
            final_url = requests.head(url, allow_redirects=True).url
            url_short = 1 if len(url) > len(final_url) else 0
        except Exception:
            url_short = 0

        return {
            'time_response': time_response,
            'domain_spf': spf_count,
            'asn_ip': asn,
            'time_domain_activation': domain_activation,
            'time_domain_expiration': domain_expiration,
            'qty_ip_resolved': resolved_ips,
            'qty_nameservers': resolved_ns,
            'qty_mx_servers': mx_servers,
            'ttl_hostname': ttl,
            'tls_ssl_certificate': tls_ssl,
            'qty_redirects': redirect,
            'url_google_index': url_google_index,
            'domain_google_index': domain_google_index,
            'url_shortened': url_short,
        }

    def getIsIndexesOnGoogle(self, url):

        try:
            google = "http://www.google.com/search?" + urlencode(url)

            data = requests.get(google, headers={
                                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0', 'referer': 'https://www.google.com/'})
            data.encoding = 'ISO-8859-1'

            soup = BeautifulSoup(str(data.content), "html.parser")
            soup.find(id="rso").find("div").find("div").find(
                "div").find("div").find("a")["href"]

            return 1
        except AttributeError:
            return 0
        except Exception:
            return -1

    def extractSymbol(self, url, prefix, default_value=-1):
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
            'qty_dot' + prefix: qty_dot if default_value != -1 else -1,
            'qty_hyphen' + prefix: qty_hyphen if default_value != -1 else -1,
            'qty_underline' + prefix: qty_underline if default_value != -1 else -1,
            'qty_slash' + prefix: qty_slash if default_value != -1 else -1,
            'qty_questionmark' + prefix: qty_questionmark if default_value != -1 else -1,
            'qty_equal' + prefix: qty_equal if default_value != -1 else -1,
            'qty_at' + prefix: qty_at if default_value != -1 else -1,
            'qty_and' + prefix: qty_and if default_value != -1 else -1,
            'qty_exclamation' + prefix: qty_exclamation if default_value != -1 else -1,
            'qty_space' + prefix: qty_space if default_value != -1 else -1,
            'qty_tilde' + prefix: qty_tilde if default_value != -1 else -1,
            'qty_comma' + prefix: qty_comma if default_value != -1 else -1,
            'qty_plus' + prefix: qty_plus if default_value != -1 else -1,
            'qty_asterisk' + prefix: qty_asterisk if default_value != -1 else -1,
            'qty_hashtag' + prefix: qty_hashtag if default_value != -1 else -1,
            'qty_dollar' + prefix: qty_dollar if default_value != -1 else -1,
            'qty_percent' + prefix: qty_percent if default_value != -1 else -1,
        }
