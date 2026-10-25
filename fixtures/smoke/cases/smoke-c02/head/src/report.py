"""Row formatting for the weekly report."""


def format_row(name, total):
    return f"{name:<20}{total:>10.2f}"


def build_report(items):
    return "\n".join(format_row(n, t) for n, t in items)
