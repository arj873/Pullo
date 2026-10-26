def summary(leases):
    return "\n".join(f"{name} held by {leases[name].owner}" for name in sorted(leases))
