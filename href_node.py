from generic_node import GenericNode


class HrefNode(GenericNode):
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, location: str):
        self.location = location
        GenericNode.__init__(self)

    def __str__(self):
        print(self.location)