from config import read_timeout


def connect(host, raw_timeout):
    return open_socket(host, timeout=read_timeout(raw_timeout))
