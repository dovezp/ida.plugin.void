#!/usr/bin/python
# coding=utf-8

"""
brief:          void - ui - context
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idaapi

    from void.resources import settings

    from void.ui.console import Console
    from void.ui.hooks import IDACtxEntry, Hooks

    from void.utilities.resources import icon
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# IDA Context Menu


class Context(object):
    def __init__(self):
        self._hooks = None
        self.console = Console()

    def setup(self):
        self._init_action_plugin_about()
        self._init_action_plugin_bug()
        self._init_action_void_functions()
        self._init_action_void_function()
        self._init_action_void_function_block()
        self._init_action_void_selection()
        self._init_action_void_instruction()
        self._init_action_void_unknown()
        self._init_action_zero_ascii()
        self._init_action_zero_data()
        self._init_action_void_data()
        self._init_hooks()

    def remove(self):
        self._hooks.unhook()
        self._del_action_plugin_about()
        self._del_action_plugin_bug()
        self._del_action_void_functions()
        self._del_action_void_function()
        self._del_action_void_function_block()
        self._del_action_void_selection()
        self._del_action_void_instruction()
        self._del_action_void_unknown()
        self._del_action_zero_ascii()
        self._del_action_zero_data()
        self._del_action_void_data()

    # ----------------------------------------------------------------------------------------------
    # Plugin Hooks

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    # ----------------------------------------------------------------------------------------------
    # Plugin Action Hooks - About

    def _init_action_plugin_about(self):
        self._about_icon_id = idaapi.load_custom_icon(icon("about.png"))
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_ABOUT,
            "About",
            IDACtxEntry(self.console.about),
            None,
            "",
            self._about_icon_id
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_plugin_about(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_ABOUT)
        idaapi.free_custom_icon(self._about_icon_id)
        self._about_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # Plugin Action Hooks - Report Bug

    def _init_action_plugin_bug(self):
        self._bug_icon_id = idaapi.load_custom_icon(icon("bug.png"))
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_BUG,
            "Report Bug",
            IDACtxEntry(self.console.bug),
            None,
            "",
            self._bug_icon_id
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_plugin_bug(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_BUG)
        idaapi.free_custom_icon(self._bug_icon_id)
        self._bug_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Functions

    def _init_action_void_functions(self):
        from void.utilities.function import nop_functions

        self._void_functions_icon_id = idaapi.load_custom_icon(icon("f.png"))
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_FUNCTIONS,        # The action name.
            "NOP Selected Function(s) (shift+f)",    # The action text.
            IDACtxEntry(nop_functions),              # The action handler.
            "(shift+f)",                             # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_functions_icon_id             # Optional: the action icon
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_functions(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_FUNCTIONS)
        idaapi.free_custom_icon(self._void_functions_icon_id)
        self._void_functions_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Function

    def _init_action_void_function(self):
        from void.utilities.function import nop_function

        self._void_function_icon_id = idaapi.load_custom_icon(icon("f.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_FUNCTION,         # The action name.
            "NOP Current Function (shift+f)",        # The action text.
            IDACtxEntry(nop_function),               # The action handler.
            "shift+f",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_function_icon_id              # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_function(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_FUNCTION)
        idaapi.free_custom_icon(self._void_function_icon_id)
        self._void_function_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Function Block

    def _init_action_void_function_block(self):
        from void.utilities.block import nop_function_block

        self._void_block_icon_id = idaapi.load_custom_icon(icon("b.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_FUNCTION_BLOCK,        # The action name.
            "NOP Current Function Block (shift+b)",           # The action text.
            IDACtxEntry(nop_function_block),                 # The action handler.
            "shift+b",                                        # Optional: action shortcut
            "",                                               # Optional: tooltip
            self._void_block_icon_id                          # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_function_block(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_FUNCTION_BLOCK)
        idaapi.free_custom_icon(self._void_block_icon_id)
        self._void_block_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Selection

    def _init_action_void_selection(self):
        from void.utilities.selection import nop_selection

        self._void_selection_icon_id = idaapi.load_custom_icon(icon("s.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_SELECTION,    # The action name.
            "NOP Current Selection (shift+s)",       # The action text.
            IDACtxEntry(nop_selection),             # The action handler.
            "shift+s",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_selection_icon_id             # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_selection(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_SELECTION)
        idaapi.free_custom_icon(self._void_selection_icon_id)
        self._void_selection_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Instruction

    def _init_action_void_instruction(self):
        from void.utilities.address import nop_instruction

        self._void_instruction_icon_id = idaapi.load_custom_icon(icon("i.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_INSTRUCTION,  # The action name.
            "NOP Current Instruction (shift+i)",     # The action text.
            IDACtxEntry(nop_instruction),           # The action handler.
            "shift+i",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_instruction_icon_id           # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_instruction(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_INSTRUCTION)
        idaapi.free_custom_icon(self._void_instruction_icon_id)
        self._void_instruction_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Unknown

    def _init_action_void_unknown(self):
        from void.utilities.address import nop_instruction

        self._void_unknown_icon_id = idaapi.load_custom_icon(icon("u.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_UNKNOWN,      # The action name.
            "NOP Current Unknown (shift+u)",         # The action text.
            IDACtxEntry(nop_instruction),           # The action handler.
            "shift+u",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_unknown_icon_id               # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_unknown(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_UNKNOWN)
        idaapi.free_custom_icon(self._void_unknown_icon_id)
        self._void_unknown_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Data

    def _init_action_void_data(self):
        from void.utilities.address import nop_instruction

        self._void_data_icon_id = idaapi.load_custom_icon(icon("d.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_DATA,         # The action name.
            "NOP Current Data (shift+d)",            # The action text.
            IDACtxEntry(nop_instruction),           # The action handler.
            "shift+d",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_data_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_data(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_DATA)
        idaapi.free_custom_icon(self._void_data_icon_id)
        self._void_data_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Zero Data

    def _init_action_zero_data(self):
        from void.utilities.address import zero_data

        self._zero_data_icon_id = idaapi.load_custom_icon(icon("d_zero.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_ZERO_DATA,    # The action name.
            "ZERO Current Data (shift+z)",           # The action text.
            IDACtxEntry(zero_data),                       # The action handler.
            "shift+z",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._zero_data_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_zero_data(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_ZERO_DATA)
        idaapi.free_custom_icon(self._zero_data_icon_id)
        self._zero_data_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Zero ASCII

    def _init_action_zero_ascii(self):
        from void.utilities.address import zero_data

        self._zero_ascii_icon_id = idaapi.load_custom_icon(icon("a_zero.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            settings.PLUGIN_ACTION_ZERO_ASCII,   # The action name.
            "ZERO Current ASCII (shift+a)",          # The action text.
            IDACtxEntry(zero_data),                       # The action handler.
            "shift+a",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._zero_ascii_icon_id                 # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_zero_ascii(self):
        idaapi.unregister_action(settings.PLUGIN_ACTION_ZERO_ASCII)
        idaapi.free_custom_icon(self._zero_ascii_icon_id)
        self._zero_ascii_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------


