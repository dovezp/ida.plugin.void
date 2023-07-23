#!/usr/bin/python
# coding=utf-8

"""
brief:          void
author:         deobfuscates
contact:        https://github.com/deobfuscates
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import os
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------


PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))