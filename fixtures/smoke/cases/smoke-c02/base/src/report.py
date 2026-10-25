"""Row formatting for the weekly report."""


def build_row(name, total):
    return f"{name:<20}{total:>10.2f}"


def build_report(items):
    return "\n".join(build_row(n, t) for n, t in items)
