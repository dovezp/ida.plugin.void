#!/usr/bin/python
# coding=utf-8

"""
brief:          void
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import os

    from void import plugin
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------


def PLUGIN_ENTRY():
    return plugin.IDAPlugin()


if __name__ == '__main__':
    PLUGIN_ENTRY()
