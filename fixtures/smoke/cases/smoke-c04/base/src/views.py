from pager import page_slice


def first_page(rows):
    return page_slice(rows, 1, 25)
