#!/usr/bin/python
# coding=utf-8

"""
brief:          ida - plugin - void
author:         dovezp
contact:        https://github.com/dovezp
version:        2020/SEP/22
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import os
    import sip
    import webbrowser
    import idc
    import idaapi
    import idautils
    from PyQt5 import QtGui, QtCore, QtWidgets
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledImportError: " + e.message)


# --------------------------------------------------------------------------------------------------
# Void Config


class VoidConfig(object):
    PLUGIN_NAME = "Void"
    PLUGIN_BUILD = "September 22, 2020"
    CHOOSER_TITLE = "Void - No Operation Generator"
    PLUGIN_COMMENT = "No Operation Generator"
    PLUGIN_REPOSITORY = "www.github.com/dovezp/ida.plugin.void"
    PLUGIN_HELP = PLUGIN_REPOSITORY + "/issues"
    PLUGIN_HOTKEY = ""
    PLUGIN_AUTHORS = "dovezp"
    PLUGIN_LICENSE = 'BSD 3-Clause "New" or "Revised" License'
    PLUGIN_SUPPORT = "liberapay.com/dovezp"
    PLUGIN_TEST = False


# --------------------------------------------------------------------------------------------------
# Void Path and Resources


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), VoidConfig.PLUGIN_NAME))


def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "resources",
        resource_name
    )


# --------------------------------------------------------------------------------------------------
# Void About and Bug


def plugin_about():
    idaapi.msg("================================================================================\n")
    idaapi.msg("[IDA] Plugin: %s, Build: %s\n" % (VoidConfig.PLUGIN_NAME,
                                                  VoidConfig.PLUGIN_BUILD))
    idaapi.msg("      Author(s): %s\n" % VoidConfig.PLUGIN_AUTHORS)
    idaapi.msg("      Repository: %s\n" % VoidConfig.PLUGIN_REPOSITORY)
    idaapi.msg("      Support: %s\n" % VoidConfig.PLUGIN_SUPPORT)
    idaapi.msg("      License: %s\n" % VoidConfig.PLUGIN_LICENSE)
    idaapi.msg("================================================================================\n")


def plugin_bug():
    idaapi.msg("[PLUGIN, %s][BUG!] report your issue to: %s/new?body=bug+found\n" % (VoidConfig.PLUGIN_NAME,
                                                                                     VoidConfig.PLUGIN_HELP))
    webbrowser.open(VoidConfig.PLUGIN_HELP + '/issues/new?body=bug+found', new=2)


# --------------------------------------------------------------------------------------------------
# IDA Ctx Entry


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


# --------------------------------------------------------------------------------------------------
# Plugin Hooks


def inject_actions(form, popup, form_type):
    """
    Inject prefix actions to popup menu(s) based on context.
    """

    # disassembly window
    if form_type == idaapi.BWN_DISASMS:
        if is_current_selection():
            idaapi.attach_action_to_popup(
                form,
                popup,
                VoidPlugin.ACTION_SELECTION,
                "Void/NOP Current Selection",
                idaapi.SETMENU_APP
            )
        else:
            if is_current_instruction():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_INSTRUCTION,
                    "Void/NOP Current Instruction",
                    idaapi.SETMENU_APP
                )
            elif is_current_unknown():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_UNKNOWN,
                    "Void/NOP Current Unknown",
                    idaapi.SETMENU_APP
                )
            elif is_current_ascii():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_ZERO_ASCII,
                    "Void/ZERO Current ASCII",
                    idaapi.SETMENU_APP
                )
            elif is_current_data():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_DATA,
                    "Void/NOP Current DATA",
                    idaapi.SETMENU_APP
                )
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_ZERO_DATA,
                    "Void/ZERO Current DATA",
                    idaapi.SETMENU_APP
                )

            if is_current_block():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_FUNCTION_BLOCK,
                    "Void/NOP Current Function Block",
                    idaapi.SETMENU_APP
                )

            if is_current_function():
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    VoidPlugin.ACTION_FUNCTION,
                    "Void/NOP Current Function",
                    idaapi.SETMENU_APP
                )

    # functions window
    elif form_type == idaapi.BWN_FUNCS:
        idaapi.attach_action_to_popup(
            form,
            popup,
            VoidPlugin.ACTION_FUNCTIONS,
            "Void/NOP Selected Function(s)",
            idaapi.SETMENU_APP
        )

    # either window
    if form_type == idaapi.BWN_DISASMS or \
            form_type == idaapi.BWN_FUNCS:
        idaapi.attach_action_to_popup(
            form,
            popup,
            VoidPlugin.ACTION_BUG,
            "Void/Report Bug"
        )
        idaapi.attach_action_to_popup(
            form,
            popup,
            VoidPlugin.ACTION_ABOUT,
            "Void/About"
        )
    return 0


class Hooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        """
        UI ready to run -- an IDA event fired when everything is spunup.

        NOTE: this is a placeholder func, it gets replaced on a live instance
        but we need it defined here for IDA 7.2+ to properly hook it.
        """
        pass

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        pass

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.

        We lump this under the (UI) Hooks class for organizational reasons.
        """
        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            pass
            #
            # if the user cursor isn't hovering over a function ref, there
            # is nothing for us to do
            #

        # done
        return 0


# --------------------------------------------------------------------------------------------------
# Void Plugin


class VoidPlugin(idaapi.plugin_t):
    """
    The IDA Plugin for Void.
    """

    flags = idaapi.PLUGIN_PROC
    comment = VoidConfig.PLUGIN_COMMENT
    help = VoidConfig.PLUGIN_HELP
    wanted_name = VoidConfig.PLUGIN_NAME
    wanted_hotkey = VoidConfig.PLUGIN_HOTKEY

    def __init__(self, *args, **kwargs):
        super(VoidPlugin, self).__init__(*args, **kwargs)
        self._hooks = None

    # ----------------------------------------------------------------------------------------------
    # Plugin Overloads

    def init(self):
        # initialize the menu actions our plugin will inject
        self._init_action_void_about()
        self._init_action_void_bug()
        self._init_action_void_functions()
        self._init_action_void_function()
        self._init_action_void_function_block()
        self._init_action_void_selection()
        self._init_action_void_instruction()
        self._init_action_void_unknown()
        self._init_action_zero_ascii()
        self._init_action_zero_data()
        self._init_action_void_data()

        # initialize plugin hooks
        self._init_hooks()

        # done
        plugin_about()
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """
        This is called by IDA when this file is loaded as a script.
        """
        plugin_about()
        return

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_void_about()
        self._del_action_void_bug()
        self._del_action_void_functions()
        self._del_action_void_function()
        self._del_action_void_function_block()
        self._del_action_void_selection()
        self._del_action_void_instruction()
        self._del_action_void_unknown()
        self._del_action_zero_ascii()
        self._del_action_zero_data()
        self._del_action_void_data()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    # ----------------------------------------------------------------------------------------------
    # Plugin Hooks

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).

        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    # ----------------------------------------------------------------------------------------------
    # IDA Actions

    ACTION_ABOUT = "void:about"
    ACTION_BUG = "void:bug"
    ACTION_INSTRUCTION = "void:instruction"
    ACTION_UNKNOWN = "void:unknown"
    ACTION_ZERO_ASCII = "void:zero-ascii"
    ACTION_ZERO_DATA = "void:zero-data"
    ACTION_DATA = "void:data"
    ACTION_SELECTION = "void:selection"
    ACTION_FUNCTION_BLOCK = "void:function_block"
    ACTION_FUNCTION = "void:function"
    ACTION_FUNCTIONS = "void:functions"

    # ----------------------------------------------------------------------------------------------
    # IDA Void Plugin

    def _init_action_void_about(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_about_icon_id = idaapi.load_custom_icon(plugin_resource("about.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_ABOUT,                         # The action name.
            "About",                                   # The action text.
            IDACtxEntry(plugin_about),                 # The action handler.
            None,                                      # Optional: action shortcut
            "",                                        # Optional: tooltip
            self._void_about_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_about(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_ABOUT)
        idaapi.free_custom_icon(self._void_about_icon_id)
        self._void_about_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Plugin

    def _init_action_void_bug(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_bug_icon_id = idaapi.load_custom_icon(plugin_resource("bug.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_BUG,                           # The action name.
            "Report Bug",                              # The action text.
            IDACtxEntry(plugin_bug),                   # The action handler.
            None,                                      # Optional: action shortcut
            "",                                        # Optional: tooltip
            self._void_bug_icon_id                     # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_bug(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_BUG)
        idaapi.free_custom_icon(self._void_bug_icon_id)
        self._void_bug_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Functions

    def _init_action_void_functions(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_functions_icon_id = idaapi.load_custom_icon(plugin_resource("f.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_FUNCTIONS,                   # The action name.
            "NOP Selected Function(s) (shift+f)",    # The action text.
            IDACtxEntry(void_functions),             # The action handler.
            "(shift+f)",                             # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_functions_icon_id             # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_functions(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_FUNCTIONS)
        idaapi.free_custom_icon(self._void_functions_icon_id)
        self._void_functions_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Function

    def _init_action_void_function(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_function_icon_id = idaapi.load_custom_icon(plugin_resource("f.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_FUNCTION,                    # The action name.
            "NOP Current Function (shift+f)",        # The action text.
            IDACtxEntry(void_function),              # The action handler.
            "shift+f",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_function_icon_id              # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_function(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_FUNCTION)
        idaapi.free_custom_icon(self._void_function_icon_id)
        self._void_function_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Function Block

    def _init_action_void_function_block(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_block_icon_id = idaapi.load_custom_icon(plugin_resource("b.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_FUNCTION_BLOCK,                       # The action name.
            "NOP Current Function Block (shift+b)",           # The action text.
            IDACtxEntry(void_function_block),                 # The action handler.
            "shift+b",                                        # Optional: action shortcut
            "",                                               # Optional: tooltip
            self._void_block_icon_id                          # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_function_block(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_FUNCTION_BLOCK)
        idaapi.free_custom_icon(self._void_block_icon_id)
        self._void_block_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Selection

    def _init_action_void_selection(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_selection_icon_id = idaapi.load_custom_icon(plugin_resource("s.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_SELECTION,                   # The action name.
            "NOP Current Selection (shift+s)",       # The action text.
            IDACtxEntry(void_selection),             # The action handler.
            "shift+s",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_selection_icon_id             # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_selection(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_SELECTION)
        idaapi.free_custom_icon(self._void_selection_icon_id)
        self._void_selection_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Instruction

    def _init_action_void_instruction(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_instruction_icon_id = idaapi.load_custom_icon(plugin_resource("i.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_INSTRUCTION,                 # The action name.
            "NOP Current Instruction (shift+i)",     # The action text.
            IDACtxEntry(void_instruction),           # The action handler.
            "shift+i",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_instruction_icon_id           # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_instruction(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_INSTRUCTION)
        idaapi.free_custom_icon(self._void_instruction_icon_id)
        self._void_instruction_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Unknown

    def _init_action_void_unknown(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_unknown_icon_id = idaapi.load_custom_icon(plugin_resource("u.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_UNKNOWN,                     # The action name.
            "NOP Current Unknown (shift+u)",         # The action text.
            IDACtxEntry(void_instruction),           # The action handler.
            "shift+u",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_unknown_icon_id               # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_unknown(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_UNKNOWN)
        idaapi.free_custom_icon(self._void_unknown_icon_id)
        self._void_unknown_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Void Data

    def _init_action_void_data(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._void_data_icon_id = idaapi.load_custom_icon(plugin_resource("d.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_DATA,                        # The action name.
            "NOP Current Data (shift+d)",            # The action text.
            IDACtxEntry(void_instruction),           # The action handler.
            "shift+d",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._void_data_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_void_data(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_DATA)
        idaapi.free_custom_icon(self._void_data_icon_id)
        self._void_data_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Zero Data

    def _init_action_zero_data(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._zero_data_icon_id = idaapi.load_custom_icon(plugin_resource("d_zero.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_ZERO_DATA,                   # The action name.
            "ZERO Current Data (shift+z)",           # The action text.
            IDACtxEntry(zero),                       # The action handler.
            "shift+z",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._zero_data_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_zero_data(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_ZERO_DATA)
        idaapi.free_custom_icon(self._zero_data_icon_id)
        self._zero_data_icon_id = idaapi.BADADDR

    # ----------------------------------------------------------------------------------------------
    # IDA Zero ASCII

    def _init_action_zero_ascii(self):
        """
        Register the action with IDA.
        """

        # load the icon for this action
        self._zero_ascii_icon_id = idaapi.load_custom_icon(plugin_resource("a_zero.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_ZERO_ASCII,                  # The action name.
            "ZERO Current ASCII (shift+a)",          # The action text.
            IDACtxEntry(zero),                       # The action handler.
            "shift+a",                               # Optional: action shortcut
            "",                                      # Optional: tooltip
            self._zero_ascii_icon_id                 # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_zero_ascii(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_ZERO_ASCII)
        idaapi.free_custom_icon(self._zero_ascii_icon_id)
        self._zero_ascii_icon_id = idaapi.BADADDR


# --------------------------------------------------------------------------------------------------
# Void Helpers


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


def is_current_block():
    current_address = idc.ScreenEA()
    f = idaapi.get_func(current_address)
    if not f:
        return

    fc = idaapi.FlowChart(f)
    for block in fc:
        if block.startEA <= current_address:
            if block.endEA > current_address:
                return True
    return False


def is_current_selection():
    selected = idaapi.read_selection()
    start_address = selected[1]
    end_address = selected[2]
    if start_address != 0 and start_address != idc.BADADDR and \
            end_address != 0 and end_address != idc.BADADDR:
        return True
    return False


def is_current_instruction():
    # is the cursor is within a instruction
    current_address = idc.ScreenEA()
    address_flags = idc.GetFlags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if idc.isCode(address_flags):
            return True
    return False


def is_current_unknown():
    # is the cursor is within unknown
    current_address = idc.ScreenEA()
    address_flags = idc.GetFlags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if idc.isUnknown(address_flags):
            return True
    return False


def is_current_ascii():
    # is the cursor is within ascii
    current_address = idc.ScreenEA()
    address_flags = idc.GetFlags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if idc.isASCII(address_flags):
            return True
    return False


def is_current_data():
    # is the cursor is within data
    current_address = idc.ScreenEA()
    address_flags = idc.GetFlags(current_address)
    if current_address != 0 and current_address != idc.BADADDR:
        if idc.isData(address_flags):
            return True
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


def refresh_views():
    """
    Refresh the IDA views.
    """

    # refresh IDA views
    idaapi.refresh_idaview_anyway()

    # refresh hexrays
    current_widget = idaapi.get_current_widget()
    vu = idaapi.get_widget_vdui(current_widget)
    if vu:
        vu.refresh_ctext()


# --------------------------------------------------------------------------------------------------
# Void API


def nop_function():
    current_address = idc.ScreenEA()
    current_function_information = idaapi.get_func(current_address)
    if not current_function_information:
        return
    current_function_name = idc.GetFunctionName(current_address)
    if not current_function_name:
        return
    start_address = current_function_information.startEA
    iterate_address = start_address
    end_address = current_function_information.endEA
    # start test
    fc = idaapi.FlowChart(current_function_information)
    for block in fc:
        for i in range(block.startEA, block.endEA):
            idc.PatchByte(i, 0x90)
    """"""
    while iterate_address < end_address:
        next_address = idc.NextHead(iterate_address)
        address_flags = idc.GetFlags(iterate_address)
        if iterate_address != 0 and iterate_address != idc.BADADDR:
            if idc.isCode(address_flags):
                instruction_size = idc.ItemSize(iterate_address)
                for i in range(instruction_size):
                    idc.PatchByte(iterate_address + i, 0x90)
        iterate_address = next_address
    refresh_views()
    return


def nop_functions():
    idaapi.msg("[PLUGIN, %s][WARNING!] filtering selected functions may take time!\n" % VoidConfig.PLUGIN_NAME)
    for func_name in get_selected_functions():
        function_address = idaapi.get_name_ea(idaapi.BADADDR, func_name)
        current_function_information = idaapi.get_func(function_address)
        if not current_function_information:
            return
        start_address = current_function_information.startEA
        iterate_address = start_address
        end_address = current_function_information.endEA
        # start test
        fc = idaapi.FlowChart(current_function_information)
        for block in fc:
            for i in range(block.startEA, block.endEA):
                idc.PatchByte(i, 0x90)
        """"""
        while iterate_address < end_address:
            next_address = idc.NextHead(iterate_address)
            address_flags = idc.GetFlags(iterate_address)
            if iterate_address != 0 and iterate_address != idc.BADADDR:
                if idc.isCode(address_flags):
                    instruction_size = idc.ItemSize(iterate_address)
                    for i in range(instruction_size):
                        idc.PatchByte(iterate_address + i, 0x90)
            iterate_address = next_address
        refresh_views()
    return


def nop_selection():
    selected = idaapi.read_selection()
    start_address = selected[1]
    end_address = selected[2]
    end_address_size = idc.ItemSize(end_address)
    for i in range(start_address, end_address + end_address_size):
        idc.PatchByte(i, 0x90)
    refresh_views()
    return


def nop_function_block():
    current_address = idc.ScreenEA()
    f = idaapi.get_func(current_address)
    if not f:
        return

    fc = idaapi.FlowChart(f)
    for block in fc:
        if block.startEA <= current_address:
            if block.endEA > current_address:
                for i in range(block.startEA, block.endEA):
                    idc.PatchByte(i, 0x90)
                break
    refresh_views()
    return


def nop_instruction():
    current_address = idc.ScreenEA()
    instruction_size = idc.ItemSize(current_address)
    for i in range(instruction_size):
        idc.PatchByte(current_address + i, 0x90)
    refresh_views()
    return


def zero_data():
    current_address = idc.ScreenEA()
    instruction_size = idc.ItemSize(current_address)
    for i in range(instruction_size):
        idc.PatchByte(current_address + i, 0x00)
    refresh_views()
    return


# --------------------------------------------------------------------------------------------------
# Void Wrappers


def void_function():
    nop_function()


def void_functions():
    nop_functions()


def void_selection():
    nop_selection()


def void_function_block():
    nop_function_block()


def void_instruction():
    nop_instruction()


def zero():
    zero_data()


# --------------------------------------------------------------------------------------------------
# Plugin Entry


def PLUGIN_ENTRY():
    return VoidPlugin()


# --------------------------------------------------------------------------------------------------
# Plugin Tester


if VoidConfig.PLUGIN_TEST:
    p = VoidPlugin()
    p.init()
    p.run()
    p.term()
