from leasing import clock
from leasing.lease import Lease


class Scheduler:
    def __init__(self):
        self.leases = {}

    def acquire(self, name, owner, ttl_ms):
        if name in self.leases:
            return False
        self.leases[name] = Lease(owner, ttl_ms)
        return True

    def reap(self):
        now = clock.now_millis()
        freed = [n for n, lease in self.leases.items() if lease.expires_at <= now]
        for name in freed:
            del self.leases[name]
        return freed
