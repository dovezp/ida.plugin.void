#!/usr/bin/python
# coding=utf-8

"""
brief:          void - plugin - resources
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import os

    from void import PLUGIN_DIR

    from void.resources import settings
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------


def path(resource_name):
    return os.path.join(PLUGIN_DIR, settings.PLUGIN_RESOURCES, resource_name)


def icon(icon_name):
    return os.path.join(PLUGIN_DIR, settings.PLUGIN_RESOURCES_ICONS, icon_name)
