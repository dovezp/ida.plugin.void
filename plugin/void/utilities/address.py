#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - address
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idc
    import ida_bytes

    from void.utilities.views import refresh_views
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Address


def is_current_instruction():
    # is the cursor is within a instruction
    current_address = idc.get_screen_ea()
    address_flags = idc.get_full_flags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if ida_bytes.is_code(address_flags):
            return True
    return False


def is_current_unknown():
    # is the cursor is within unknown
    current_address = idc.get_screen_ea()
    address_flags = idc.get_full_flags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if ida_bytes.is_unknown(address_flags):
            return True
    return False


def is_current_ascii():
    # is the cursor is within ascii
    current_address = idc.get_screen_ea()
    address_flags = idc.get_full_flags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if ida_bytes.is_strlit(address_flags):
            return True
    return False


def is_current_data():
    # is the cursor is within data
    current_address = idc.get_screen_ea()
    address_flags = idc.get_full_flags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if ida_bytes.is_data(address_flags):
            return True
    return False


def nop_instruction():
    current_address = idc.get_screen_ea()
    instruction_size = idc.get_item_size(current_address)
    for i in range(instruction_size):
        ida_bytes.patch_byte(current_address + i, 0x90)
    refresh_views()
    return


def zero_data():
    current_address = idc.get_screen_ea()
    instruction_size = idc.get_item_size(current_address)
    for i in range(instruction_size):
        ida_bytes.patch_byte(current_address + i, 0x00)
    refresh_views()
    return

