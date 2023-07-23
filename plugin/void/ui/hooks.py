#!/usr/bin/python
# coding=utf-8

"""
brief:          void - ui - hooks
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idaapi

    from void.resources import settings

    from void.utilities import address, block, function, selection, views, widget
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# IDA Ctx Entry


class IDACtxEntry(idaapi.action_handler_t):

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# --------------------------------------------------------------------------------------------------
# Plugin Hooks


def inject_actions(form, popup, form_type):

    # disassembly window
    if form_type == idaapi.BWN_DISASMS:
        if selection.is_current_selection():
            idaapi.attach_action_to_popup(
                form,
                popup,
                settings.PLUGIN_ACTION_SELECTION,
                "Void/NOP Current Selection",
                idaapi.SETMENU_APP
            )
        else:
            if address.is_current_instruction():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_INSTRUCTION,
                    "Void/NOP Current Instruction",
                    idaapi.SETMENU_APP
                )
            elif address.is_current_unknown():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_UNKNOWN,
                    "Void/NOP Current Unknown",
                    idaapi.SETMENU_APP
                )
            elif address.is_current_ascii():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_ZERO_ASCII,
                    "Void/ZERO Current ASCII",
                    idaapi.SETMENU_APP
                )
            elif address.is_current_data():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_DATA,
                    "Void/NOP Current DATA",
                    idaapi.SETMENU_APP
                )
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_ZERO_DATA,
                    "Void/ZERO Current DATA",
                    idaapi.SETMENU_APP
                )

            if block.is_current_block():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_FUNCTION_BLOCK,
                    "Void/NOP Current Function Block",
                    idaapi.SETMENU_APP
                )

            if function.is_current_function():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    settings.PLUGIN_ACTION_FUNCTION,
                    "Void/NOP Current Function",
                    idaapi.SETMENU_APP
                )

    # functions window
    elif form_type == idaapi.BWN_FUNCS:
        idaapi.attach_action_to_popup(
            form,
            popup,
            settings.PLUGIN_ACTION_FUNCTIONS,
            "Void/NOP Selected Function(s)",
            idaapi.SETMENU_APP
        )

    # either window
    if form_type == idaapi.BWN_DISASMS or \
            form_type == idaapi.BWN_FUNCS:
        idaapi.attach_action_to_popup(
            form,
            popup,
            settings.PLUGIN_ACTION_BUG,
            "Void/Report Bug"
        )
        idaapi.attach_action_to_popup(
            form,
            popup,
            settings.PLUGIN_ACTION_ABOUT,
            "Void/About"
        )
    return 0


class Hooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        pass

    def finish_populating_widget_popup(self, widget, popup):
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        pass

    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            pass
        return 0
