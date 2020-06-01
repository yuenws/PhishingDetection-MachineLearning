import sys
from bs4 import BeautifulSoup 
import ipaddress
import requests
import whois
import datetime
import numpy as np 
import wordsegment
import re
import tldextract

LOCALHOST_PATH = "D:/xampp/htdocs/FYP/"
DIRECTORY_NAME = "Code"

def having_ip_address(url):
    count=0
    splitURL = url.split("/")
    for parts in splitURL:
        try: 
            ip_address = ipaddress.ip_address(parts)
            if ip_address.version in [4,6]:
                count+=1
        except ValueError:
            pass
    if count==0:
        return 1
    else: 
        return 0 

def prefix_suffix(url):
    if url.count('-')==0:
        return 1 
    else: 
        return 0

def url_length(url):
    if len(url) < 54:
        return 1 
    else: 
        return 0

def domain_num(url):
    dotcount=0
    splitURL = url.split("/")
    dotcount = splitURL[2].count('.')
    if dotcount<=3:
        return 1 
    else: 
        return 0

def phishyword(url):
    BoW=["limited", "securewebsession", "confirmation", "page", "signin", 
    "team", "sign","access", "protection","active", "manage", "redirectme", "http", "secure", "customer",
    "account", "client", "information", "recovery", "verify", "secured", "busines", "refund",
    "help", "safe", "bank", "event", "promo", "webservis", "giveaway", "card", "webspace",
    "user", "notify", "servico", "store", "device", "payment", "webnode", "drive", "shop",
    "gold", "violation", "random", "upgrade", "dispute", "setting", "banking",
    "activity", "startup", "review", "email", "approval", "admin", "browser", "webapp",
    "billing", "advert", "protect", "case", "temporary", "alert", "portal", "servehttp",
    "center", "restore", "blob", "smart", "fortune", "gift", "server",
    "security", "confirm", "notification", "core", "host", "central", "service",
    "servise", "support", "apps", "form", "info", "compute", "verification",
    "check", "storage", "digital", "update", "token", "required", "resolution",
    "ebayisapi", "webscr", "login", "free", "lucky", "bonus"]
    words=[]
    found=False
    try:
        splitURL = re.split(r'[^\w]', url)
        for parts in splitURL:
            words.extend(wordsegment.segment(parts))
        for word in words:
            if word in BoW:
                found=True
        if found:
            return 0
        else: 
            return 1
    except Exception as e:
        return 0

def port(url):
    splitURL = url.split("/")
    if ":" in splitURL[2]:
        host = splitURL[2].split(":")
        if host[1] in ["80","8008","8080","443"]:
            return 1 
        else: 
            return 0
    else: 
        return 1 

def javascriptKeyword(url):
    keyword=[]
    popup=["alert(", "confirm(", "prompt(", "open("]
    popupExist=False
    match=0
    try:
        page = requests.get(url,timeout=3)
        soup = BeautifulSoup(page.text, 'html.parser')
        if str(soup).find('<iframe')==-1:
            keyword.append(1)
        else:
            keyword.append(0)
        #    
        if str(soup).find('onmouseover')==-1:
            keyword.append(1)
        else:
            keyword.append(0)
        #
        for i in popup:
            if str(soup).find(i)!=-1:
                popupExist=True
        if popupExist:
            keyword.append(0)
        else:
            keyword.append(1)
        
        #RequestURL
        srcURLs = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-:<-@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(soup))
        extracted = tldextract.extract(url)
        targetDomain = extracted.domain+"."+extracted.suffix
        for srcURL in srcURLs:
            extracted = tldextract.extract(srcURL)
            if targetDomain == extracted.domain+"."+extracted.suffix:
                match+=1
        if len(srcURLs)>0:
            if len(srcURLs)/2 <match:
                keyword.append(1)
            else:
                keyword.append(0)
        else: keyword.append(1)
        return keyword
    except Exception as e:
        return [0,0,0,0]

def domain_age(url):
    domain=[]
    try:
        u = whois.whois(url)
        if isinstance(u.creation_date,list):
            phish=False
            for date in u.creation_date:
                if datetime.datetime.now()-date < datetime.timedelta(days=365):
                    phish=True
            if phish:
                domain.append(0)
            else: 
                domain.append(1)
        elif datetime.datetime.now()-u.creation_date < datetime.timedelta(days=365):
                domain.append(0)
        else: 
            domain.append(1)
        #
        if isinstance(u.expiration_date,list):
            phish=False
            for date in u.expiration_date:
                if date-datetime.datetime.now() < datetime.timedelta(days=365):
                    phish=True
            if phish:
                domain.append(0)
            else: 
                domain.append(1)
        elif u.expiration_date-datetime.datetime.now() < datetime.timedelta(days=365):
                domain.append(0)
        else: 
            domain.append(1)
        return domain
    except Exception as e:
        return [0,0]

def redirection(url):
    try:
        r=requests.get(url, timeout=3)
        statusCode=[]
        redir=0
        for i, resp in enumerate(r.history, 1):
            statusCode.append(resp.status_code)
        statusCode.append(r.status_code)
        for i in statusCode:
            if i >=300 and i < 400:
                redir+=1
        if redir>0:
            return 0 
        else: 
            return 1
    except Exception as e:
        return 0

wordsegment.load()
def main(link):
    wordsegment.load()
    datalist=[]

    datalist.append(having_ip_address(link))
    datalist.append(prefix_suffix(link))
    datalist.append(url_length(link))
    datalist.append(domain_num(link))
    datalist.append(phishyword(link))
    datalist.append(port(link))
    datalist.extend(javascriptKeyword(link))
    datalist.extend(domain_age(link))
    datalist.append(redirection(link))

    return datalist