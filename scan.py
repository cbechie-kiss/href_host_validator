#!/usr/bin/env python3

import urllib.request
from bs4 import BeautifulSoup
import sys
import hashlib
import re


class HrefLink:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, location, is_offsite, is_enumerated, occurrences):
        self.location = location
        self.is_offsite = is_offsite
        self.is_enumerated = is_enumerated
        self.occurrences = occurrences

class HrefList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, hrefs, total, total_on_site, num_enumerated):
        self.hrefs = hrefs  # []
        self.total = total  # 0
        self.total_on_site = total_on_site  # 0
        self.num_enumerated = num_enumerated  # 0


class Host:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, name, hash, href_list, is_in_scope, is_enumerated):
        self.name = name  # str()
        self.hash = hash  # str()
        self.href_list = href_list  # []
        self.is_in_scope = is_in_scope  # bool
        self.is_enumerated = is_enumerated   # bool

class HostList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, hosts, total, num_in_scope, num_enumerated):
        self.hosts = hosts  # []
        self.total = total  # 0
        self.num_in_scope = num_in_scope  # 0
        self.num_enumerated = num_enumerated  # 0


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
Hosts = HostList.__new__(HostList)
server_ip = ""
server_port = ""
base_url = ""


def get_web_page(domain, webpage):
    print("Retrieving Webpage: " + domain + "/" + webpage)

    req = urllib.request.Request(base_url + ":" + server_port + "/" + webpage, headers={"Host": domain, "User-Agent": USER_AGENT}, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        return None

    return resp


def is_hash_dup(new_host):
    for host in Hosts.hosts:
        if host.hash == new_host.hash:
            return True
    return False


def is_name_dup(name):
    for host in Hosts.hosts:
        if host.name == name:
            return True
    return False


def test_host(domain):
    if is_name_dup(domain) is True:
        return None
    new_host = Host.__new__(Host)
    new_host.__init__("", "", [], False, False)
    new_host.name = domain
    new_host.href_list = HrefList.__new__(HrefList)

    new_host.href_list.__init__([], 0, 0, 0)

    print("Testing Host: " + domain)
    req = urllib.request.Request(base_url + ":" + server_port, headers={"Host": domain, "User-Agent": USER_AGENT}, method="GET")

    try:
        resp = urllib.request.urlopen(req, timeout=30)
    except Exception as exc:
        print(new_host.name)
        print(exc)
        return None

    if resp.status == 404:
        return None

    new_host.hash = hashlib.sha256(resp.read()).hexdigest()



    if (len(Hosts.hosts) != 0) and (is_hash_dup(new_host) is False):
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    elif len(Hosts.hosts) == 0:
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    else:
        new_host.is_in_scope = False

    Hosts.hosts.append(new_host)
    Hosts.total = Hosts.total + 1


def accumulate(attributes_so_far, key, value):
    if not isinstance(attributes_so_far[key], list):
        attributes_so_far[key] = [attributes_so_far[key]]
    attributes_so_far[key].append(value)


def is_dup_href(host, location):
    for href in host.href_list.hrefs:
        if href.location == location:
            href.occurrences = href.occurrences + 1
            return True
    return False


def is_href_offsite(host, href):
    href.location = str(href.location)
    #print(href.location)
    if len(href.location.strip()) == 0:
        href.is_offsite = False
        href.is_enumerated = True
    elif host.name in href.location:
        if (href.location[0:7] == "http://") or (href.location[0:8] == "https://"):
            href.location = href.location.split('//', 1)[1]
        if "/" in href.location:
             href.location = href.location.split('/', 1)[1]
        href.is_offsite = False
        href.is_enumerated = False
    elif href.location[0] == "/":
        href.is_offsite = False
        href.is_enumerated = False
    elif href.location[0] == "#":
        href.is_offsite = False
        href.is_enumerated = False
    elif href.location[0:7] == "mailto:":
        href.is_offsite = False
        href.is_enumerated = True
    elif href.location[0:4] == "tel:":
        href.is_offsite = False
        href.is_enumerated = True
    elif (href.location[0:7] != "http://") and (href.location[0:8] != "https://"):
        href.is_offsite = False
        href.is_enumerated = False
    else:
        href.is_offsite = True
        href.is_enumerated = False

    if href.is_offsite is False:
        host.href_list.total_on_site = host.href_list.total_on_site + 1

    if href.is_enumerated is True:
        host.href_list.num_enumerated = host.href_list.num_enumerated + 1


def create_new_href(host, new_href):
    href = HrefLink.__new__(HrefLink)
    href.__init__(new_href, False, False, 1)
    is_href_offsite(host, href)
    host.href_list.hrefs.append(href)
    host.href_list.total = host.href_list.total + 1


def parse_for_href(host, html_doc):
    soup = BeautifulSoup(html_doc.read(), 'html.parser', on_duplicate_attribute=accumulate)
    for anchor in soup.find_all('a'):
        hrefs = anchor.get('href')

        if type(hrefs) == list:
            for location in hrefs:
                if host.name in location:
                    if (location[0:7] == "http://") or (location[0:8] == "https://"):
                        location = location.split('//', 1)[1]
                    if "/" in location:
                        location = location.split('/', 1)[1]
                if is_dup_href(host, str(location)) is False:
                    create_new_href(host, str(location))
        else:
            if host.name in hrefs:
                if (hrefs[0:7] == "http://") or (hrefs[0:8] == "https://"):
                    hrefs = hrefs.split('//', 1)[1]
                if "/" in hrefs:
                    hrefs = hrefs.split('/', 1)[1]

            if is_dup_href(host, str(hrefs)) is False:
                create_new_href(host, str(hrefs))



def enumerate_site(host):
    resp = get_web_page(host.name, "")
    parse_for_href(host, resp)
    # Do Href.is_enumerated
    '''
    for href in host.href_list.hrefs:
        if(href.is_offsite is False):
            print(href.location)
    '''
    is_all_enumerated = False
    while is_all_enumerated is False:
        for href in host.href_list.hrefs:
            if (href.is_offsite is False) and (href.is_enumerated is False):
                resp = get_web_page(host.name, href.location)
                if resp is not None:
                    parse_for_href(host, resp)
                href.is_enumerated = True
                host.href_list.num_enumerated = host.href_list.num_enumerated + 1
                #print(str(host.href_list.num_enumerated) + " "  + str(host.href_list.total_on_site))
        if host.href_list.total_on_site == host.href_list.num_enumerated:
            is_all_enumerated = True

    for href in host.href_list.hrefs:
        if(href.is_offsite is True) and (href.is_enumerated is False):
            if(href.location[0:7] == "http://") or (href.location[0:8] == "https://"):
                href.location = href.location.split('//', 1)[1]
            if "/" in href.location:
                href.location = href.location.split('/', 1)[0]
            href.is_enumerated = True
            test_host(href.location)

    host.is_enumerated = True
    Hosts.num_enumerated = Hosts.num_enumerated + 1

def print_host():
    for host in Hosts.hosts:
        print("===========================================")
        print(host.name)
        print(host.hash)
        for href in host.href_list.hrefs:
            print(href.is_enumerated, href.location)
        print("isEnumerated: ", host.is_enumerated)
        print("isInScope: ", host.is_in_scope)
        print("===========================================")


def printNewHostsFileEntries():
    host_file_edits = []

    for this_host in Hosts.hosts:
        if (this_host.is_in_scope is True) and (this_host.name != server_ip):
            host_file_edits.append(server_ip + "    " + this_host.name)

    if len(host_file_edits) != 0:
        print("Add the following to your hosts file: ")
        for this_host in host_file_edits:
            print(this_host)
    else:
        print("Nothing to add to the hosts file")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: href_parser.py <ip> <port> <base_url>")
    Hosts.__init__([], 0, 0, 0)
    server_ip = sys.argv[1]
    server_port = sys.argv[2]
    base_url = sys.argv[3]
    test_host(server_ip)

    is_all_enumerated = False
    while is_all_enumerated is False:

        if Hosts.num_enumerated == Hosts.num_in_scope:
          is_all_enumerated = True
        else:
            for host in Hosts.hosts:
                if host.is_in_scope is True and host.is_enumerated is False:
                    enumerate_site(host)

    print_host()
    printNewHostsFileEntries()


