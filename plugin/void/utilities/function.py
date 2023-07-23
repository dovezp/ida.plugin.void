#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - function
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import sip

    import idc
    import idaapi
    import idautils
    import ida_bytes

    from PyQt5 import QtGui, QtCore, QtWidgets

    from void.resources import settings

    from void.utilities.views import refresh_views
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Function


def is_current_function():
    """
     Get the function under the user cursor.

     Return True or False
     """
    current_widget = idaapi.get_current_widget()
    form_type = idaapi.get_widget_type(current_widget)
    vu = idaapi.get_widget_vdui(current_widget)
    if vu:
        # hexrays view is active
        cursor_addr = vu.item.get_ea()
    elif form_type == idaapi.BWN_DISASM:
        # disassembly view is active
        cursor_addr = idaapi.get_screen_ea()
    else:
        # fail: unsupported/unknown view is active
        # print(form_type)
        return False

    # is the cursor is within a function
    cursor_func = idaapi.get_func(cursor_addr)
    if cursor_func and \
            cursor_func.start_ea <= cursor_addr <= cursor_func.end_ea:
        return True

    # fail: unsupported/unknown view is active
    # print(form_type)
    return False


def match_functions(qt_funcs):
    res = set()
    ida_funcs = set(idaapi.get_func_name(ea) for ea in idautils.Functions())
    for f in qt_funcs:
        for f2 in ida_funcs:
            if len(f) == len(f2):
                i = 0
                while i < len(f) and (f[i] == f2[i] or f[i] == '_'):
                    i += 1
                if i == len(f):
                    res.add(f2)
                    break
    return list(res)


def nop_function():
    current_address = idc.get_screen_ea()
    current_function_information = idaapi.get_func(current_address)
    if not current_function_information:
        return
    current_function_name = idc.get_func_name(current_address)
    if not current_function_name:
        return
    start_address = current_function_information.start_ea
    iterate_address = start_address
    end_address = current_function_information.end_ea
    # start test
    fc = idaapi.FlowChart(current_function_information)
    for block in fc:
        for i in range(block.start_ea, block.end_ea):
            ida_bytes.patch_byte(i, 0x90)
    """"""
    while iterate_address < end_address:
        next_address = idc.next_head(iterate_address)
        address_flags = ida_bytes.get_full_flags(iterate_address)
        if iterate_address != 0 and iterate_address != idc.BADADDR:
            if ida_bytes.is_code(address_flags):
                instruction_size = idc.get_item_size(iterate_address)
                for i in range(instruction_size):
                    ida_bytes.patch_byte(iterate_address + i, 0x90)
        iterate_address = next_address
    refresh_views()
    return


# --------------------------------------------------------------------------------------------------
# Functions


def get_selected_functions():
    """
    Return the list of function names selected in the Functions window.
    """
    twidget = idaapi.find_widget("Functions window")
    widget = sip.wrapinstance(int(twidget), QtWidgets.QWidget)

    # TODO: test this
    if not widget:
        idaapi.warning("Unable to find 'Functions window'")
        return

    table = widget.findChild(QtWidgets.QTableView)
    selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]
    return match_functions(selected_funcs)

def nop_functions():
    # idaapi.msg("[PLUGIN, %s][WARNING!] filtering selected functions may take time!\n" % settings.PLUGIN_NAME)
    for func_name in get_selected_functions():
        function_address = idaapi.get_name_ea(idaapi.BADADDR, func_name)
        current_function_information = idaapi.get_func(function_address)
        if not current_function_information:
            return
        start_address = current_function_information.start_ea
        iterate_address = start_address
        end_address = current_function_information.end_ea
        # start test
        fc = idaapi.FlowChart(current_function_information)
        for block in fc:
            for i in range(block.start_ea, block.end_ea):
                ida_bytes.patch_byte(i, 0x90)
        """"""
        while iterate_address < end_address:
            next_address = idc.next_head(iterate_address)
            address_flags = ida_bytes.get_full_flags(iterate_address)
            if iterate_address != 0 and iterate_address != idc.BADADDR:
                if ida_bytes.is_code(address_flags):
                    instruction_size = idc.get_item_size(iterate_address)
                    for i in range(instruction_size):
                        ida_bytes.patch_byte(iterate_address + i, 0x90)
            iterate_address = next_address
        refresh_views()
    return
