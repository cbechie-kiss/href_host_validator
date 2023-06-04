from typing import List


class GenericList:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self):
        self.list: List = []
        self.total_nodes: int = 0
        self.num_in_scope: int = 0
        self.num_enumerated: int = 0
        self.total_on_site: int = 0

    def __str__(self):
        for node in self.list:
            print(node.__str__())
