from urllib.parse import urlencode
import signal
import pandas as pd
import urllib.parse
import tldextract
import requests
import json
import csv
import os
import re
import time

from urllib.parse import urlparse
from bs4 import BeautifulSoup

key = 'Add your OPR API key here'

HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js',
         'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

# class TimedOutExc(Exception):
#     pass

# def deadline(timeout, *args):
#     def decorate(f):
#         def handler(signum, frame):
#             raise TimedOutExc()

#         def new_f(*args):
#             signal.signal(signal.SIGALRM, handler)
#             signal.alarm(timeout)
#             return f(*args)
#             signal.alarm(0)

#         new_f.__name__ = f.__name__
#         return new_f
#     return decorate

# @deadline(5)


def is_URL_accessible(url):
    # iurl = url
    # parsed = urlparse(url)
    # url = parsed.scheme+'://'+parsed.netloc
    page = None
    try:
        if not url.startswith("https://"):
            page = requests.get('https://'+url, timeout=1)
            url = "https://"+url
        else:
            page = requests.get(url, timeout=1)
    except:
        # parsed = urlparse(url)
        # url = parsed.scheme+'://'+parsed.netloc
        if not url.startswith("http://"):
            try:
                page = requests.get('http://'+url, timeout=1)
                url = "http://"+url
            except:
                pass

        # if not parsed.netloc.startswith('www'):
        #     url = parsed.scheme+'://www.'+parsed.netloc
        #     try:
        #         page = requests.get(url, timeout=5)
        #     except:
        #         page = None
        #         pass
        # if not parsed.netloc.startswith('www'):
        #     url = parsed.scheme+'://www.'+parsed.netloc
        #     #iurl = iurl.replace('https://', 'https://www.')
        #     try:
        #         page = requests.get(url)
        #     except:
        #         # url = 'http://'+parsed.netloc
        #         # iurl = iurl.replace('https://', 'http://')
        #         # try:
        #         #     page = requests.get(url)
        #         # except:
        #         #     if not parsed.netloc.startswith('www'):
        #         #         url = parsed.scheme+'://www.'+parsed.netloc
        #         #         iurl = iurl.replace('http://', 'http://www.')
        #         #         try:
        #         #             page = requests.get(url)
        #         #         except:
        #         #             pass
        #         pass
    if page and page.status_code <= 301 and page.content not in ["b''", "b' '"]:
        return True, url, page
    else:
        return False, url, None


def words_raw_extraction(domain, subdomain, path):
    w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
    w_subdomain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
    w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
    raw_words = w_domain + w_path + w_subdomain
    w_host = w_domain + w_subdomain
    raw_words = list(filter(None, raw_words))
    return raw_words, list(filter(None, w_host)), list(filter(None, w_path))

# length_url


def url_length(url):

    return len(url)

# length_hostname


def get_domain(url):

    o = urllib.parse.urlsplit(url)
    return o.hostname, o.path

#


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        # IPv4 in hexadecimal
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0


def count_dots(hostname):
    return hostname.count('.')


def count_exclamation(base_url):
    return base_url.count('?')


def count_equal(base_url):
    return base_url.count('=')


def count_slash(full_url):
    return full_url.count('/')


def check_www(words_raw):
    count = 0
    for word in words_raw:
        if not word.find('www') == -1:
            count += 1
    return count


def ratio_digits(hostname):
    return len(re.sub("[^0-9]", "", hostname))/len(hostname)


def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld) > 0:
        return 1
    return 0


def prefix_suffix(url):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0


def longest_word_length(words_raw):
    if len(words_raw) == 0:
        return 0
    return max(len(word) for word in words_raw)


def shortest_word_length(words_raw):
    if len(words_raw) == 0:
        return 0
    return min(len(word) for word in words_raw)


def phish_hints(url_path):
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count


def nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['internals']) + len(Href['externals']) +\
        len(Link['internals']) + len(Link['externals']) +\
        len(Media['internals']) + len(Media['externals']) +\
        len(Form['internals']) + len(Form['externals']) +\
        len(CSS['internals']) + len(CSS['externals']) +\
        len(Favicon['internals']) + len(Favicon['externals'])


def h_total(Href, Link, Media, Form, CSS, Favicon):
    return nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)


def h_internal(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['internals']) + len(Link['internals']) + len(Media['internals']) +\
        len(Form['internals']) + len(CSS['internals']) + \
        len(Favicon['internals'])


def internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    if total == 0:
        return 0
    else:
        return h_internal(Href, Link, Media, Form, CSS, Favicon)/total


def empty_title(Title):
    if Title:
        return 0
    return 1


def domain_in_title(domain, title):

    if str(domain).lower() in str(title).lower():

        return 0
    return 1


def domain_age(domain):
    domain_name = whois.whois(domain)
    if type(domain_name.creation_date) == list:
        creation_date = domain_name.creation_date[0]
    else:
        creation_date = domain_name.creation_date

    if type(domain_name.expiration_date) == list:
        expiration_date = domain_name.expiration_date[0]
    else:
        expiration_date = domain_name.expiration_date

    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(
                expiration_date, "%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        return abs((expiration_date - creation_date).days)


def google_index(url):
    # time.sleep(.6)
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent': user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        # print(check)
        if check and check['href']:
            return 0
        else:
            return 1

    except AttributeError:
        return 1


def page_rank(domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(
            url, headers={'API-OPR': 'g0g8k0k44g0cggkokckkgw0gws88wcw0k4s8gg8c'})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


def extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
                   "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]
    try:
        soup = BeautifulSoup(content, 'html.parser',
                             from_encoding='iso-8859-1')

        # collect all external and internal hrefs from url
        for href in soup.find_all('a', href=True):
            dots = [x.start(0) for x in re.finditer('\.', href['href'])]
            if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
                if not href['href'].startswith('http'):
                    if not href['href'].startswith('/'):
                        Href['internals'].append(hostname+'/'+href['href'])
                    elif href['href'] in Null_format:
                        Href['null'].append(href['href'])
                    else:
                        Href['internals'].append(hostname+href['href'])
            else:
                Href['externals'].append(href['href'])

        # collect all media src tags
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
                if not img['src'].startswith('http'):
                    if not img['src'].startswith('/'):
                        Media['internals'].append(hostname+'/'+img['src'])
                    elif img['src'] in Null_format:
                        Media['null'].append(img['src'])
                    else:
                        Media['internals'].append(hostname+img['src'])
            else:
                Media['externals'].append(img['src'])

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
                if not audio['src'].startswith('http'):
                    if not audio['src'].startswith('/'):
                        Media['internals'].append(hostname+'/'+audio['src'])
                    elif audio['src'] in Null_format:
                        Media['null'].append(audio['src'])
                    else:
                        Media['internals'].append(hostname+audio['src'])
            else:
                Media['externals'].append(audio['src'])

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
                if not embed['src'].startswith('http'):
                    if not embed['src'].startswith('/'):
                        Media['internals'].append(hostname+'/'+embed['src'])
                    elif embed['src'] in Null_format:
                        Media['null'].append(embed['src'])
                    else:
                        Media['internals'].append(hostname+embed['src'])
            else:
                Media['externals'].append(embed['src'])

        for i_frame in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
            if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('http'):
                    if not i_frame['src'].startswith('/'):
                        Media['internals'].append(hostname+'/'+i_frame['src'])
                    elif i_frame['src'] in Null_format:
                        Media['null'].append(i_frame['src'])
                    else:
                        Media['internals'].append(hostname+i_frame['src'])
            else:
                Media['externals'].append(i_frame['src'])

        # collect all link tags
        for link in soup.findAll('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
                if not link['href'].startswith('http'):
                    if not link['href'].startswith('/'):
                        Link['internals'].append(hostname+'/'+link['href'])
                    elif link['href'] in Null_format:
                        Link['null'].append(link['href'])
                    else:
                        Link['internals'].append(hostname+link['href'])
            else:
                Link['externals'].append(link['href'])

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith('http'):
                if not script['src'].startswith('http'):
                    if not script['src'].startswith('/'):
                        Link['internals'].append(hostname+'/'+script['src'])
                    elif script['src'] in Null_format:
                        Link['null'].append(script['src'])
                    else:
                        Link['internals'].append(hostname+script['src'])
            else:
                Link['externals'].append(script['href'])

        # collect all css
        for link in soup.find_all('link', rel='stylesheet'):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
                if not link['href'].startswith('http'):
                    if not link['href'].startswith('/'):
                        CSS['internals'].append(hostname+'/'+link['href'])
                    elif link['href'] in Null_format:
                        CSS['null'].append(link['href'])
                    else:
                        CSS['internals'].append(hostname+link['href'])
            else:
                CSS['externals'].append(link['href'])

        for style in soup.find_all('style', type='text/css'):
            try:
                start = str(style[0]).index('@import url(')
                end = str(style[0]).index(')')
                css = str(style[0])[start+12:end]
                dots = [x.start(0) for x in re.finditer('\.', css)]
                if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                    if not css.startswith('http'):
                        if not css.startswith('/'):
                            CSS['internals'].append(hostname+'/'+css)
                        elif css in Null_format:
                            CSS['null'].append(css)
                        else:
                            CSS['internals'].append(hostname+css)
                else:
                    CSS['externals'].append(css)
            except:
                continue

        # collect all form actions
        for form in soup.findAll('form', action=True):
            dots = [x.start(0) for x in re.finditer('\.', form['action'])]
            if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith('http'):
                if not form['action'].startswith('http'):
                    if not form['action'].startswith('/'):
                        Form['internals'].append(hostname+'/'+form['action'])
                    elif form['action'] in Null_format or form['action'] == 'about:blank':
                        Form['null'].append(form['action'])
                    else:
                        Form['internals'].append(hostname+form['action'])
            else:
                Form['externals'].append(form['action'])

        # collect all link tags
        for head in soup.find_all('head'):
            for head.link in soup.find_all('link', href=True):
                dots = [x.start(0)
                        for x in re.finditer('\.', head.link['href'])]
                if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                    if not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('/'):
                            Favicon['internals'].append(
                                hostname+'/'+head.link['href'])
                        elif head.link['href'] in Null_format:
                            Favicon['null'].append(head.link['href'])
                        else:
                            Favicon['internals'].append(
                                hostname+head.link['href'])
                else:
                    Favicon['externals'].append(head.link['href'])

            for head.link in soup.findAll('link', {'href': True, 'rel': True}):
                isicon = False
                if isinstance(head.link['rel'], list):
                    for e_rel in head.link['rel']:
                        if (e_rel.endswith('icon')):
                            isicon = True
                else:
                    if (head.link['rel'].endswith('icon')):
                        isicon = True

                if isicon:
                    dots = [x.start(0)
                            for x in re.finditer('\.', head.link['href'])]
                    if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('http'):
                            if not head.link['href'].startswith('/'):
                                Favicon['internals'].append(
                                    hostname+'/'+head.link['href'])
                            elif head.link['href'] in Null_format:
                                Favicon['null'].append(head.link['href'])
                            else:
                                Favicon['internals'].append(
                                    hostname+head.link['href'])
                    else:
                        Favicon['externals'].append(head.link['href'])
    except:
        pass
    # collect i_frame

    # get page title
    try:
        Title = soup.title.string
    except:
        pass

    # get content text
    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text


def url_row(url, page, hostname, domain, path, words_raw, words_raw_host, words_raw_path, tld, subdomain, Href, Link, Media, Form, CSS, Favicon, Title):
    row = [
        url_length(url),
        url_length(hostname),
        having_ip_address(url),
        count_dots(hostname),
        count_exclamation(url),
        count_equal(url),
        count_slash(url),
        check_www(words_raw),
        ratio_digits(url),
        ratio_digits(hostname),
        tld_in_subdomain(tld, subdomain),
        prefix_suffix(url),
        shortest_word_length(words_raw_host),
        longest_word_length(words_raw),
        longest_word_length(words_raw_path),
        phish_hints(url),
        nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
        internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
        empty_title(Title),
        domain_in_title(hostname, Title),
        # domain_age(domain),
        # google_index(url),
        page_rank(domain)
    ]
    return row


def url_extractor(url, page):
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Anchor = {'safe': [], 'unsafe': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    IFrame = {'visible': [], 'invisible': [], 'null': []}
    Title = ''
    Text = ''
    content = page.content
    hostname, path = get_domain(url)
    extracted_domain = tldextract.extract(url)
    domain = extracted_domain.domain+'.'+extracted_domain.suffix
    subdomain = extracted_domain.subdomain
    tmp = url[url.find(extracted_domain.suffix):len(url)]
    pth = tmp.partition("/")
    path = pth[1] + pth[2]
    words_raw, words_raw_host, words_raw_path = words_raw_extraction(
        extracted_domain.domain, subdomain, pth[2])
    tld = extracted_domain.suffix

    Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = extract_data_from_URL(
        hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text)

    res = url_row(url, page, hostname, domain, path, words_raw, words_raw_host,
                  words_raw_path, tld, subdomain, Href, Link, Media, Form, CSS, Favicon, Title)
    return res
