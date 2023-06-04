from generic_node import GenericNode


class EmailNode(GenericNode):
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, domain, address):
        self.domain = domain
        self.address = address
        GenericNode.__init__(self)

    def __str__(self):
        print(self.address)
