from generic_node import GenericNode
from generic_list import GenericList


class HostNode(GenericNode):
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, name: str, _hash: str, href_list: GenericList, email_list: GenericList):
        self.name = name
        self.hash = _hash
        self.href_list = href_list
        self.email_list = email_list
        GenericNode.__init__(self)

    def __str__(self):
        print("Name: " + self.name)
        print("Hash " + self.hash)