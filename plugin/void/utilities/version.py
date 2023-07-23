#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - version
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idc
    import idaapi
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Version


def supported_version():
    if idaapi.IDA_SDK_VERSION >= 750:
        return True
    return False
