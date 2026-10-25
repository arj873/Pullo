"""Pagination helpers."""


def page_slice(rows, page, size):
    offset = page * size
    return rows[offset:offset + size]
