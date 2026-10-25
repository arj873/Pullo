"""A tiny bounded cache."""


class Cache:
    def __init__(self, limit):
        self.limit = limit
        self.items = {}

    def put(self, key, value):
        self.items[key] = value
        while len(self.items) > self.limit:
            self.items.pop(next(iter(self.items)))

    def get(self, key):
        return self.items.get(key)
