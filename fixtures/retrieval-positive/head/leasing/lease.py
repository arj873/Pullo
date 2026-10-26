from leasing import clock


class Lease:
    def __init__(self, owner, ttl_ms):
        self.owner = owner
        self.expires_at = clock.now_millis() + ttl_ms

    def renew(self, ttl_ms):
        self.expires_at = clock.now_millis() + ttl_ms
