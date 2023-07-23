#!/usr/bin/python
# coding=utf-8

"""
brief:          void - ui - console
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idaapi

    from void.resources import settings
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# IDA Console Output


class Console(object):
    def __init__(self):
        pass

    def about(self):
        idaapi.msg("================================================================================\n")
        idaapi.msg("[IDA] Plugin: %s\n" % settings.PLUGIN_TITLE)
        idaapi.msg("      Build: %s\n" % settings.PLUGIN_BUILD)
        idaapi.msg("      Developer(s): %s\n" % settings.PLUGIN_DEVELOPERS)
        idaapi.msg("      Repository: %s\n" % settings.PLUGIN_REPOSITORY)
        idaapi.msg("      License: %s\n" % settings.PLUGIN_LICENSE)
        idaapi.msg("================================================================================\n")

    def bug(self):
        idaapi.msg("[PLUGIN, %s][Bug Found!] Report your issue to: %s/new?body=bug+found\n" % (settings.PLUGIN_NAME,
                                                                                               settings.PLUGIN_HELP))
        try:
            import webbrowser
            webbrowser.open(settings.PLUGIN_HELP + '/issues/new?body=bug+found', new=2)
        except Exception as e:
            pass
