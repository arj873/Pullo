"""Runtime settings."""


def read_timeout(raw):
    return int(raw) if raw else 0
