from bs4 import BeautifulSoup

class Parser:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __int__(self):
        self.string_to_parse = None
        self.string_processing = None
        self.string_parsed = None

    def separate_from_https(self, string: str):
        self.string_to_parse = string
        if (self.string_to_parse[0:7] == "http://") or (self.string_to_parse[0:8] == "https://"):
            self.string_processing = self.string_to_parse.split('//', 1)[1]
        self.string_parsed = self.string_processing
        return self.string_parsed

    def separate_location_from_host(self, string: str):
        self.separate_from_https(string)
        if "/" in self.string_processing:
            self.string_processing = self.string_processing.split('/', 1)[1]
        self.string_parsed = self.string_processing
        return self.string_parsed

    def separate_host_from_location(self, string: str):
        self.separate_from_https(string)
        if "/" in self.string_processing:
            self.string_processing = self.string_processing.split('/', 1)[0]
        self.string_parsed = self.string_processing
        return self.string_parsed
