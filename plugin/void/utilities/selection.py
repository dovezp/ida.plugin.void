#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - selection
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idc
    import idaapi
    import ida_bytes

    from void.utilities.views import refresh_views
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Selection


def is_current_selection():
    # selected = idaapi.read_selection()
    p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    if idaapi.read_selection(view, p0, p1):
        start_address = p0.place(view).ea  # selected[1]
        end_address = p1.place(view).ea  # selected[2]
        if start_address != 0 and start_address != idc.BADADDR and \
                end_address != 0 and end_address != idc.BADADDR:
            return True
    return False


def nop_selection():
    # selected = idaapi.read_selection()
    p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    if idaapi.read_selection(view, p0, p1):
        start_address = p0.place(view).ea # selected[1]
        end_address = p1.place(view).ea # selected[2]
        end_address_size = idc.get_item_size(end_address)
        for i in range(start_address, end_address + end_address_size):
            ida_bytes.patch_byte(i, 0x90)
        refresh_views()
    return
