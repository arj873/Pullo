from cache import Cache

recent = Cache(limit=2)


def remember(key, value):
    recent.put(key, value)
    assert len(recent.items) <= recent.limit
