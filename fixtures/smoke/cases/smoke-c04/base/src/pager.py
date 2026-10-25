"""Pagination helpers."""


def page_slice(rows, page, size):
    offset = (page - 1) * size
    return rows[offset:offset + size]
