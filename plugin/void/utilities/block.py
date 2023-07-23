#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - block
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
# Block


def is_current_block():
    current_address = idc.get_screen_ea()
    f = idaapi.get_func(current_address)
    if not f:
        return

    fc = idaapi.FlowChart(f)
    for block in fc:
        if block.start_ea <= current_address:
            if block.end_ea > current_address:
                return True
    return False


def nop_function_block():
    current_address = idc.get_screen_ea()
    f = idaapi.get_func(current_address)
    if not f:
        return

    fc = idaapi.FlowChart(f)
    for block in fc:
        if block.start_ea <= current_address:
            if block.end_ea > current_address:
                for i in range(block.start_ea, block.end_ea):
                    ida_bytes.patch_byte(i, 0x90)
                break
    refresh_views()
    return

