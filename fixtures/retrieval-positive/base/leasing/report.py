def summary(leases):
    lines = []
    for name in sorted(leases):
        lease = leases[name]
        lines.append(name + " held by " + lease.owner)
    return "\n".join(lines)
