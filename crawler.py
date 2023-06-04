#!/usr/bin/env python3

import urllib.request
import requests
from bs4 import BeautifulSoup
import sys
import hashlib
import re
from generic_list import GenericList
from email_node import EmailNode
from href_node import HrefNode
from host_node import HostNode


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
Hosts = GenericList.__new__(GenericList)
server_ip = ""
server_port = ""
base_url = ""
DEBUG = 0


def is_local_ipv4_private_address():
    # Regular expression pattern to match local IPv4 private addresses. ChatGPT
    pattern = r'^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern, server_ip))


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


def is_hash_dup(new_host):
    if Hosts.list is not None:
        for host in Hosts.list:
            if host.hash == new_host.hash:
                return True
    return False


def is_name_dup(name):
    if Hosts.list is not None:
        for host in Hosts.list:
            if host.name == name:
                return True
    return False


def is_a_email_domain(new_host):
    if len(Hosts.list) != 0:
        original_host = Hosts.list[0]
        if original_host.hash == new_host.hash:
            for email in original_host.email_list.list:
                if email.domain == new_host.name:
                    return True


def to_crawl_or_not_to_crawl(domain):
    ans = input("Do you want to crawl " + domain + " (y/N): ").lower()
    if (ans == "y") or (ans == "yes"):
        return True
    else:
        return False


def test_host(domain):
    # Prompt user if they want to crawl domain
    if is_name_dup(domain) is True:
        return None
    new_host = HostNode.__new__(HostNode)
    new_host.__init__("", "", [], [])
    new_host.name = domain
    new_host.href_list = GenericList.__new__(GenericList)
    new_host.email_list = GenericList.__new__(GenericList)

    new_host.href_list.__init__()
    new_host.email_list.__init__()

    local = is_local_ipv4_private_address()

    if local is False:
        new_host.is_in_scope = to_crawl_or_not_to_crawl(domain)

    if new_host.is_in_scope is False:
        new_host.is_enumerated = False
        Hosts.list.append(new_host)
        Hosts.total_nodes= Hosts.total_nodes + 1
        return

    print("Testing Host: " + domain)
    req = urllib.request.Request(base_url, headers={"Host": separate_host_from_location(domain),
                                                    "User-Agent": USER_AGENT}, method="GET")
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
    elif (len(Hosts.list) != 0) and (is_hash_dup(new_host) is False):
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    elif len(Hosts.list) == 0:
        # First time through the hosts len will be 0
        new_host.is_in_scope = True
        Hosts.num_in_scope = Hosts.num_in_scope + 1
    else:
        new_host.is_in_scope = False

    Hosts.list.append(new_host)
    Hosts.total_nodes = Hosts.total_nodes + 1


def get_web_page(domain, webpage):

    if (len(webpage.strip()) != 0) and (webpage[0] == "/"):
        webpage = webpage[1:]

    print("Retrieving Webpage: " + base_url + "/" + urllib.parse.unquote(webpage))
    header = {"Host": separate_host_from_location(domain), "User-Agent": USER_AGENT}
    if domain in host.name:
        try:
            resp = requests.get(base_url + "/" + webpage, headers=header)
        except Exception as exc:
            return None
        return resp.content


def accumulate(attributes_so_far, key, value):
    if not isinstance(attributes_so_far[key], list):
        attributes_so_far[key] = [attributes_so_far[key]]
    attributes_so_far[key].append(value)


def is_dup_href(host: HostNode, location):
    for href in host.href_list.list:
        if href.location == location:
            href.occurrences = href.occurrences + 1
            return True
    return False


def is_href_offsite(host: HostNode, href):
    href.location = str(href.location)

    if len(href.location.strip()) == 0:
        href.is_offsite = False
        href.is_enumerated = True
    elif re.match(r"^[/#]", href.location):
        href.is_offsite = False
        href.is_enumerated = False
    elif re.match(r"^(mailto:|tel:)", href.location):
        href.is_offsite = False
        href.is_enumerated = True
    elif not re.match(r"^(http://|https://)", href.location):
        href.is_offsite = False
        href.is_enumerated = False
    else:
        href.is_offsite = True
        href.is_enumerated = False

    if href.is_offsite is False:
        host.href_list.total_on_site = host.href_list.total_on_site + 1

    if href.is_enumerated is True:
        host.href_list.num_enumerated = host.href_list.num_enumerated + 1


def create_new_href(host: HostNode, new_href):
    href = HrefNode.__new__(HrefNode)
    href.__init__(new_href)
    is_href_offsite(host, href)
    host.href_list.list.append(href)
    host.href_list.total = host.href_list.total_nodes + 1


def driver_create_href(host: HostNode, location):

    if location[0:8] == "mailto:":
        return
    if DEBUG == 1:
        print("driver_create_href:" + str(location))
    if host.name in location:
        location = separate_location_from_host(location)
    if is_dup_href(host, str(location)) is False:
        create_new_href(host, str(location))


def parse_for_href(host: HostNode, soup):
    #print(soup.prettify())
    for anchor in soup.find_all('a'):
        hrefs = anchor.get('href')

        #print("PARSE_FOR_HREFS:" + str(hrefs))
        if hrefs is not None:
            if type(hrefs) == list:
                for location in hrefs:
                    driver_create_href(host, location)
            else:
                driver_create_href(host, hrefs)


def enumerate_hrefs(host: HostNode):
    is_all_enumerated = False
    while is_all_enumerated is False:
        for href in host.href_list.list:
            if (href.is_offsite is False) and (href.is_enumerated is False):
                resp = get_web_page(host.name, href.location)
                soup = BeautifulSoup(resp, 'html.parser', on_duplicate_attribute=accumulate)
                if resp is not None:
                    parse_for_href(host, soup)
                href.is_enumerated = True
                host.href_list.num_enumerated = host.href_list.num_enumerated + 1
                if DEBUG == 1:
                    print(str(host.href_list.num_enumerated) + " " + str(host.href_list.total_on_site))
        if host.href_list.total_on_site == host.href_list.num_enumerated:
            is_all_enumerated = True


def test_href_for_new_site(host: HostNode):
    for href in host.href_list.list:
        if(href.is_offsite is True) and (href.is_enumerated is False):
            if DEBUG == 1:
                print(href.location)
            href.is_enumerated = True
            test_host(separate_host_from_location(href.location))


def test_email_for_new_site(host: HostNode):
    for email in host.email_list.list:
        if(email.is_offsite is True) and (email.is_enumerated is False):
            if DEBUG == 1:
                print("TEST EMAIL:" + email.domain)
            email.is_enumerated = True
            test_host(email.domain)
            host.email_list.num_enumerated = host.email_list.num_enumerated + 1


def test_host_for_new_sites(host: HostNode):
    test_href_for_new_site(host)
    test_email_for_new_site(host)


def is_email_dup(host: HostNode, email):
    if len(host.email_list.list) != 0:
        for this_email in host.email_list.list:
            if this_email.address == email:
                this_email.occurrences = this_email.occurrences + 1
                return True
    return False


def extract_emails(text):
    # ChatGPT generated
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(pattern, text, re.IGNORECASE)

    unique_emails = list(set(emails))
    return unique_emails


def extract_emails_from_html(html):
    # ChatGPT generated
    clean_html = re.sub('<[^<]+?>', '', html)
    emails = extract_emails(clean_html)
    return emails


def create_new_email(host: HostNode, email):
    if is_email_dup(host, email) is False:
        new_email = EmailNode.__new__(EmailNode)
        domain = email.split("@", 1)[1]
        new_email.__init__(domain, email)
        new_email.occurrences = 1
        host.email_list.list.append(new_email)
        if new_email.domain == host.name:
            new_email.is_offsite = False
            new_email.is_enumerated = True


def parse_for_emails(host: HostNode, soup):

    emails = extract_emails_from_html(soup.prettify())

    if emails:
        for email in emails:
            if DEBUG == 1:
                print("EMAIL FOUND: " + str(email))
            create_new_email(host, email)


def enumerate_site(host: HostNode):
    resp = get_web_page(host.name, "")
    soup = BeautifulSoup(resp, 'html.parser', on_duplicate_attribute=accumulate)
    parse_for_href(host, soup)
    parse_for_emails(host, soup)
    if DEBUG == 1:
        print("Enum Hrefs")
    enumerate_hrefs(host)
    if DEBUG == 1:
        print("Enum Emails")
    test_host_for_new_sites(host)

    host.is_enumerated = True
    Hosts.num_enumerated = Hosts.num_enumerated + 1
    if DEBUG == 1:
        print("Enum Finished")


def print_emails(host: HostNode):
    if len(host.email_list.list) != 0:
        print("Emails Found: ")
        for email in host.email_list.list:
            print("\t" + email.address)
    else:
        print("No emails found")


def print_host():
    for host in Hosts.list:
        print("===========================================")
        print("Name: " + host.name)
        print("Hash: " + host.hash)
        for href in host.href_list.list:
            if href is not None:
                if href.is_offsite is False:
                    print(urllib.parse.unquote(href.location))
        print("isEnumerated: ", host.is_enumerated)
        print("isInScope: ", host.is_in_scope)
        print_emails(host)
        print("===========================================")


def print_new_hosts_file_entries():
    host_file_edits = []

    for this_host in Hosts.list:
        if (this_host.is_in_scope is True) and (this_host.name != server_ip) and (this_host.name != base_url):
            host_file_edits.append(server_ip + "    " + this_host.name)

    if len(host_file_edits) != 0:
        print("Add the following to your hosts file: ")
        for this_host in host_file_edits:
            print(this_host)
    else:
        print("Nothing to add to the hosts file")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: crawler.py <ip> <port> <base_url>")
        exit(-1)
    Hosts.__init__()
    server_ip = sys.argv[1]
    server_port = sys.argv[2]
    base_url = sys.argv[3]

    test_host(base_url)

    is_all_enumerated = False
    while is_all_enumerated is False:

        if Hosts.num_enumerated == Hosts.num_in_scope:
          is_all_enumerated = True
        else:
            for host in Hosts.list:
                if host.is_in_scope is True and host.is_enumerated is False:
                    enumerate_site(host)

    print_host()
    print_new_hosts_file_entries()