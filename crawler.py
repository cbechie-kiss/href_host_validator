import urllib.request
import requests
import urllib.parse

class Crawler:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, server_ip, server_port, base_url, user_agent):

        self.server_ip = server_ip
        self.server_port = server_port
        self.base_url = base_url
        self.user_agent = user_agent

    def make_test_connection(self, domain, host_name):
        print("Testing Host: " + domain)
        req = urllib.request.Request(self.base_url,
                                     headers={"Host": domain,
                                              "User-Agent": self.user_agent},
                                     method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=30)
        except Exception as exc:
            print(host_name + " with exception: ")
            print(exc)
            return None

        if resp.status == 404:
            return None

        return resp

    def get_web_page(self, domain, webpage, host_name):

        if (len(webpage.strip()) != 0) and (webpage[0] == "/"):
            webpage = webpage[1:]

        print("Retrieving Webpage: " + self.base_url + "/" + urllib.parse.unquote(webpage))
        header = {"Host": domain, "User-Agent": self.user_agent}
        if domain in host_name:
            try:
                resp = requests.get(self.base_url + "/" + webpage, headers=header)
            except Exception as exc:
                return None
            return resp.content
