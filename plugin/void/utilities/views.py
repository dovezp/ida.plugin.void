#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - views
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idaapi
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Views


def refresh_views():
    # refresh IDA views
    idaapi.refresh_idaview_anyway()

    current_widget = idaapi.get_current_widget()
    form_type = idaapi.get_widget_type(current_widget)
    vu = idaapi.get_widget_vdui(current_widget)
    if vu or form_type == idaapi.BWN_PSEUDOCODE:
        # refresh hexrays
        vu.refresh_ctext()

