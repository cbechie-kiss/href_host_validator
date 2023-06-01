#!/usr/bin/env python3

import urllib.request
from bs4 import BeautifulSoup
import sys
import hashlib
import re
from typing import List


class HrefLink:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, location: str, is_offsite: bool, is_enumerated: bool, occurrences: int):
        self.location = location
        self.is_offsite = is_offsite
        self.is_enumerated = is_enumerated
        self.occurrences = occurrences


class HrefList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, hrefs: List[HrefLink], total: int, total_on_site: int, num_enumerated: int):
        self.hrefs = hrefs  # []
        self.total = total  # 0
        self.total_on_site = total_on_site  # 0
        self.num_enumerated = num_enumerated  # 0


class Email:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, address: str, domain: str, is_offsite: bool, is_enumerated: bool, occurrences: int):
        self.address = address  # ""
        self.domain = domain  # ""
        self.is_offsite = is_offsite  # bool
        self.is_enumerated = is_enumerated  # bool
        self.occurrences = occurrences # 0


class EmailList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, emails: List[Email], total: int, total_on_site: int, num_enumerated: int):
        self.emails = emails  # []
        self.total = total  # 0
        self.total_on_site = total_on_site  # 0
        self.num_enumerated = num_enumerated  # 0


class Host:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, name: str, _hash: str, href_list: HrefList, email_list: EmailList,
                 is_in_scope: bool, is_enumerated: bool):
        self.name = name  # str()
        self.hash = _hash  # str()
        self.href_list = href_list  #
        self.email_list = email_list  #
        self.is_in_scope = is_in_scope  # bool
        self.is_enumerated = is_enumerated   # bool


class HostList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, hosts: List[Host], total: int, num_in_scope: int, num_enumerated: int):
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
    print("Retrieving Webpage: " + domain + "/" + urllib.parse.unquote(webpage))

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


def is_a_email_domain(new_host):
    if len(Hosts.hosts) != 0 :
        original_host = Hosts.hosts[0]
        if original_host.hash == new_host.hash:
            for email in original_host.email_list.emails:
                if email.domain == new_host.name:
                    return True


def test_host(domain):
    if is_name_dup(domain) is True:
        return None
    new_host = Host.__new__(Host)
    new_host.__init__("", "", [], [], False, False)
    new_host.name = domain
    new_host.href_list = HrefList.__new__(HrefList)
    new_host.email_list = EmailList.__new__(EmailList)

    new_host.href_list.__init__([], 0, 0, 0)
    new_host.email_list.__init__([], 0, 0, 0)

    print("Testing Host: " + domain)
    req = urllib.request.Request(base_url + ":" + server_port, headers={"Host": domain, "User-Agent": USER_AGENT}, method="GET")

    try:
        #print(req.host + " " + str(req.headers))
        resp = urllib.request.urlopen(req, timeout=30)
    except Exception as exc:
        print(new_host.name)
        print(exc)
        return None

    if resp.status == 404:
        return None

    new_host.hash = hashlib.sha256(resp.read()).hexdigest()


    if is_a_email_domain(new_host) is True:
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    elif (len(Hosts.hosts) != 0) and (is_hash_dup(new_host) is False):
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    elif len(Hosts.hosts) == 0:
        # First time through the hosts len will be 0
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


def is_dup_href(host: Host, location):
    for href in host.href_list.hrefs:
        if href.location == location:
            href.occurrences = href.occurrences + 1
            return True
    return False


def is_href_offsite(host: Host, href):
    href.location = str(href.location)
    #print(href.location)
    if len(href.location.strip()) == 0:
        href.is_offsite = False
        href.is_enumerated = True
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


def create_new_href(host: Host, new_href):
    href = HrefLink.__new__(HrefLink)
    href.__init__(new_href, False, False, 1)
    is_href_offsite(host, href)
    host.href_list.hrefs.append(href)
    host.href_list.total = host.href_list.total + 1


def separate_location_from_host(location):
    if (location[0:7] == "http://") or (location[0:8] == "https://"):
        location = location.split('//', 1)[1]
    if "/" in location:
         location = location.split('/', 1)[1]
    return location


def separate_host_from_location(location):
    if (location[0:7] == "http://") or (location[0:8] == "https://"):
        location = location.split('//', 1)[1]
    if "/" in location:
         location = location.split('/', 1)[0]
    return location


def driver_create_href(host: Host, location):
    if host.name in location:
        location = separate_location_from_host(location)
    if is_dup_href(host, str(location)) is False:
        create_new_href(host, str(location))


def parse_for_href(host: Host, soup):
    for anchor in soup.find_all('a'):
        hrefs = anchor.get('href')

        if type(hrefs) == list:
            for location in hrefs:
                driver_create_href(host, location)
        else:
            driver_create_href(host, hrefs)


def enumerate_hrefs(host: Host, soup):
    is_all_enumerated = False
    while is_all_enumerated is False:
        for href in host.href_list.hrefs:
            if (href.is_offsite is False) and (href.is_enumerated is False):
                resp = get_web_page(host.name, href.location)
                if resp is not None:
                    parse_for_href(host, soup)
                href.is_enumerated = True
                host.href_list.num_enumerated = host.href_list.num_enumerated + 1
                #print(str(host.href_list.num_enumerated) + " "  + str(host.href_list.total_on_site))
        if host.href_list.total_on_site == host.href_list.num_enumerated:
            is_all_enumerated = True


def test_href_for_new_site(host: Host):
    for href in host.href_list.hrefs:
        if(href.is_offsite is True) and (href.is_enumerated is False):
            #print(href.location)
            href.location = separate_host_from_location(href.location)
            href.is_enumerated = True
            test_host(href.location)


def test_email_for_new_site(host: Host):
    for email in host.email_list.emails:
        if(email.is_offsite is True) and (email.is_enumerated is False):
            #print(href.location)
            email.is_enumerated = True
            test_host(email.domain)
            host.email_list.num_enumerated = host.email_list.num_enumerated + 1


def test_host_for_new_sites(host: Host):
    test_href_for_new_site(host)
    test_email_for_new_site(host)


def is_email_dup(host: Host, email):
    if len(host.email_list.emails) != 0:
        for this_email in host.email_list.emails:
            if this_email.address == email:
                this_email.occurrences = this_email.occurrences + 1
                return True
    return False


def create_new_email(host: Host, email):
    if is_email_dup(host, email) is False:
        new_email = Email.__new__(Email)
        new_email.__init__("", "", True, False, 0)
        new_email.address = email
        new_email.domain = email.split("@", 1)[1]
        new_email.occurrences = 1
        host.email_list.emails.append(new_email)
        if new_email.domain == host.name:
            new_email.is_offsite = False
            new_email.is_enumerated = True


def parse_for_emails(host: Host, soup):
    extract_email_pattern = r"\S+@\S+\.\S+"
    emails = re.findall(extract_email_pattern, soup.prettify())
    if emails:
        for email in emails:
            create_new_email(host, email)


def enumerate_site(host: Host):
    resp = get_web_page(host.name, "")
    soup = BeautifulSoup(resp.read(), 'html.parser', on_duplicate_attribute=accumulate)
    parse_for_href(host, soup)
    parse_for_emails(host, soup)

    #  print("Enum Hrefs")
    enumerate_hrefs(host, soup)
    #  print("Enum Emails")
    test_host_for_new_sites(host)

    host.is_enumerated = True
    Hosts.num_enumerated = Hosts.num_enumerated + 1
    #  print("Enum Finished")


def print_emails(host: Host):
    if len(host.email_list.emails) != 0:
        print("Emails Found: ")
        for email in host.email_list.emails:
            print("\t" + email.address)
    else:
        print("No emails found")


def print_host():
    for host in Hosts.hosts:
        print("===========================================")
        print(host.name)
        print(host.hash)
        for href in host.href_list.hrefs:
            print(urllib.parse.unquote(href.location))
        print("isEnumerated: ", host.is_enumerated)
        print("isInScope: ", host.is_in_scope)
        print_emails(host)
        print("===========================================")


def print_new_hosts_file_entries():
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
    print_new_hosts_file_entries()


