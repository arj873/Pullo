import time


def now_seconds():
    return time.time()


def now_millis():
    return int(time.time() * 1000)
