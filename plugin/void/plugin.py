#!/usr/bin/python
# coding=utf-8

"""
brief:          void - plugin
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import os

    import idaapi

    from void.resources import settings

    from void.ui import console
    from void.ui import context

    from void.utilities import version
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# IDA Plugin


class IDAPlugin(idaapi.plugin_t):
    flags = None
    comment = None
    help = None
    wanted_name = None
    wanted_hotkey = None

    def __init__(self, *args, **kwargs):
        super(IDAPlugin, self).__init__(*args, **kwargs)
        if version.supported_version():
            self.context = context.Context()
            self.console = console.Console()
            self.__plugin()
        else:
            idaapi.msg("[PLUGIN, %s][ERROR!] Not supported for current IDA version\n" % settings.PLUGIN_NAME)

    def __plugin(self):
        self.flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
        self.comment = settings.PLUGIN_COMMENT
        self.help = settings.PLUGIN_HELP
        self.wanted_name = settings.PLUGIN_NAME
        self.wanted_hotkey = settings.PLUGIN_HOTKEY

    # ----------------------------------------------------------------------------------------------
    # Plugin Overloads

    def init(self):
        self.context.setup()
        self.console.about()
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        self.console.about()
        return

    def term(self):
        self.context.remove()
        pass
