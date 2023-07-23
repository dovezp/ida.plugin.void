#!/usr/bin/python
# coding=utf-8

"""
brief:          void - utilities - widget
author:         dovezp
contact:        https://github.com/dovezp
version:        2021/JAN/08
license:        BSD 3-Clause "New" or "Revised" License
"""

try:
    import idaapi

    from enum import Enum
except ImportError as e:
    raise e
except Exception as e:
    raise e


# --------------------------------------------------------------------------------------------------
# Widgets


class Widgets(Enum):
    BWN_UNKNOWN = idaapi.BWN_UNKNOWN
    """
    unknown window
    """

    BWN_EXPORTS = idaapi.BWN_EXPORTS
    """
    exports
    """

    BWN_IMPORTS = idaapi.BWN_IMPORTS
    """
    imports
    """

    BWN_NAMES = idaapi.BWN_NAMES
    """
    names
    """

    BWN_FUNCS = idaapi.BWN_FUNCS
    """
    functions
    """

    BWN_STRINGS = idaapi.BWN_STRINGS
    """
    strings
    """

    BWN_SEGS = idaapi.BWN_SEGS
    """
    segments
    """

    BWN_SEGREGS = idaapi.BWN_SEGREGS
    """
    segment registers
    """

    BWN_SELS = idaapi.BWN_SELS
    """
    selectors
    """

    BWN_SIGNS = idaapi.BWN_SIGNS
    """
    signatures
    """

    BWN_TILS = idaapi.BWN_TILS
    """
    type libraries
    """

    BWN_LOCTYPS = idaapi.BWN_LOCTYPS
    """
    local types
    """

    BWN_CALLS = idaapi.BWN_CALLS
    """
    function calls
    """

    BWN_PROBS = idaapi.BWN_PROBS
    """
    problems
    """

    BWN_BPTS = idaapi.BWN_BPTS
    """
    breakpoints
    """

    BWN_THREADS = idaapi.BWN_THREADS
    """
    threads
    """

    BWN_MODULES = idaapi.BWN_MODULES
    """
    modules
    """

    BWN_TRACE = idaapi.BWN_TRACE
    """
    trace view
    """

    BWN_CALL_STACK = idaapi.BWN_CALL_STACK
    """
    call stack
    """

    BWN_XREFS = idaapi.BWN_XREFS
    """
    xrefs
    """

    BWN_SEARCH = idaapi.BWN_SEARCH
    """
    search results
    """

    BWN_FRAME = idaapi.BWN_FRAME
    """
    function frame
    """

    BWN_NAVBAND = idaapi.BWN_NAVBAND
    """
    navigation band
    """

    BWN_ENUMS = idaapi.BWN_ENUMS
    """
    enumerations
    """

    BWN_STRUCTS = idaapi.BWN_STRUCTS
    """
    structures
    """

    BWN_DISASM = idaapi.BWN_DISASM
    """
    disassembly views
    """

    BWN_DUMP = idaapi.BWN_DUMP
    """
    hex dumps
    """

    BWN_NOTEPAD = idaapi.BWN_NOTEPAD
    """
    notepad
    """

    BWN_OUTPUT = idaapi.BWN_OUTPUT
    """
    the text area, in the output window
    """

    BWN_CLI = idaapi.BWN_CLI
    """
    the command-line, in the output window
    """

    BWN_WATCH = idaapi.BWN_WATCH
    """
    the 'watches' debugger window
    """

    BWN_LOCALS = idaapi.BWN_LOCALS
    """
    the 'locals' debugger window
    """

    BWN_STKVIEW = idaapi.BWN_STKVIEW
    """
    the 'Stack view' debugger window
    """

    BWN_CHOOSER = idaapi.BWN_CHOOSER
    """
    a non-builtin chooser
    """

    BWN_SHORTCUTCSR = idaapi.BWN_SHORTCUTCSR
    """
    the shortcuts chooser (Qt version only)
    """

    BWN_SHORTCUTWIN = idaapi.BWN_SHORTCUTWIN
    """
    the shortcuts window (Qt version only)
    """

    BWN_CPUREGS = idaapi.BWN_CPUREGS
    """
    one of the 'General registers', 'FPU register', ... debugger windows
    """

    BWN_SO_STRUCTS = idaapi.BWN_SO_STRUCTS
    """
    the 'Structure offsets' dialog's 'Structures and Unions' panel
    """

    BWN_SO_OFFSETS = idaapi.BWN_SO_OFFSETS
    """
    the 'Structure offsets' dialog's offset panel
    """

    BWN_CMDPALCSR = idaapi.BWN_CMDPALCSR
    """
    the command palette chooser (Qt version only)
    """

    BWN_CMDPALWIN = idaapi.BWN_CMDPALWIN
    """
    the command palette window (Qt version only)
    """

    BWN_SNIPPETS = idaapi.BWN_SNIPPETS
    """
    the 'Execute script' window
    """

    BWN_CUSTVIEW = idaapi.BWN_CUSTVIEW
    """
    custom viewers
    """

    BWN_ADDRWATCH = idaapi.BWN_ADDRWATCH
    """
    the 'Watch List' window
    """

    BWN_PSEUDOCODE = idaapi.BWN_PSEUDOCODE
    """
    hexrays decompiler views
    """

    BWN_CALLS_CALLERS = idaapi.BWN_CALLS_CALLERS
    """
    function calls, callers
    """

    BWN_CALLS_CALLEES = idaapi.BWN_CALLS_CALLEES
    """
    function calls, callees
    """

    BWN_MDVIEWCSR = idaapi.BWN_MDVIEWCSR
    """
    lumina metadata view chooser
    """

    BWN_DISASM_ARROWS = idaapi.BWN_DISASM_ARROWS
    """
    disassembly arrows widget
    """

    BWN_CV_LINE_INFOS = idaapi.BWN_CV_LINE_INFOS
    """
    custom viewers' lineinfo widget
    """

    BWN_SRCPTHMAP_CSR = idaapi.BWN_SRCPTHMAP_CSR
    """
    "Source paths..."'s path mappings chooser
    """

    BWN_SRCPTHUND_CSR = idaapi.BWN_SRCPTHUND_CSR
    """
    "Source paths..."'s undesired paths chooser
    """

    BWN_UNDOHIST = idaapi.BWN_UNDOHIST
    """
    Undo history.
    """

    BWN_SNIPPETS_CSR = idaapi.BWN_SNIPPETS_CSR
    """
    the list of snippets in the 'Execute script' window
    """

    BWN_SCRIPTS_CSR = idaapi.BWN_SCRIPTS_CSR
    """
    the "Recent scripts" chooser
    """

    BWN_STACK = idaapi.BWN_STACK
    """
    Alias. Some BWN_* were confusing, and thus have been renamed. This is
    to ensure bw-compat.
    """

    BWN_DISASMS = idaapi.BWN_DISASMS
    """
    Alias. Some BWN_* were confusing, and thus have been renamed. This is
    to ensure bw-compat.
    """

    BWN_DUMPS = idaapi.BWN_DUMPS
    """
    Alias. Some BWN_* were confusing, and thus have been renamed. This is
    to ensure bw-compat.
    """

    BWN_SEARCHS = idaapi.BWN_SEARCHS
    """
    Alias. Some BWN_* were confusing, and thus have been renamed. This is
    to ensure bw-compat.
    """

    IWID_EXPORTS = idaapi.IWID_EXPORTS
    """
    exports (0)
    """

    IWID_IMPORTS = idaapi.IWID_IMPORTS
    """
    imports (1)
    """

    IWID_NAMES = idaapi.IWID_NAMES
    """
    names (2)
    """

    IWID_FUNCS = idaapi.IWID_FUNCS
    """
    functions (3)
    """

    IWID_STRINGS = idaapi.IWID_STRINGS
    """
    strings (4)
    """

    IWID_SEGS = idaapi.IWID_SEGS
    """
    segments (5)
    """

    IWID_SEGREGS = idaapi.IWID_SEGREGS
    """
    segment registers (6)
    """

    IWID_SELS = idaapi.IWID_SELS
    """
    selectors (7)
    """

    IWID_SIGNS = idaapi.IWID_SIGNS
    """
    signatures (8)
    """

    IWID_TILS = idaapi.IWID_TILS
    """
    type libraries (9)
    """

    IWID_LOCTYPS = idaapi.IWID_LOCTYPS
    """
    local types (10)
    """

    IWID_CALLS = idaapi.IWID_CALLS
    """
    function calls (11)
    """

    IWID_PROBS = idaapi.IWID_PROBS
    """
    problems (12)
    """

    IWID_BPTS = idaapi.IWID_BPTS
    """
    breakpoints (13)
    """

    IWID_THREADS = idaapi.IWID_THREADS
    """
    threads (14)
    """

    IWID_MODULES = idaapi.IWID_MODULES
    """
    modules (15)
    """

    IWID_TRACE = idaapi.IWID_TRACE
    """
    trace view (16)
    """

    IWID_CALL_STACK = idaapi.IWID_CALL_STACK
    """
    call stack (17)
    """

    IWID_XREFS = idaapi.IWID_XREFS
    """
    xrefs (18)
    """

    IWID_SEARCH = idaapi.IWID_SEARCH
    """
    search results (19)
    """

    IWID_FRAME = idaapi.IWID_FRAME
    """
    function frame (25)
    """

    IWID_NAVBAND = idaapi.IWID_NAVBAND
    """
    navigation band (26)
    """

    IWID_ENUMS = idaapi.IWID_ENUMS
    """
    enumerations (27)
    """

    IWID_STRUCTS = idaapi.IWID_STRUCTS
    """
    structures (28)
    """

    IWID_DISASM = idaapi.IWID_DISASM
    """
    disassembly views (29)
    """

    IWID_DUMP = idaapi.IWID_DUMP
    """
    hex dumps (30)
    """

    IWID_NOTEPAD = idaapi.IWID_NOTEPAD
    """
    notepad (31)
    """

    IWID_OUTPUT = idaapi.IWID_OUTPUT
    """
    output (32)
    """

    IWID_CLI = idaapi.IWID_CLI
    """
    input line (33)
    """

    IWID_WATCH = idaapi.IWID_WATCH
    """
    watches (34)
    """

    IWID_LOCALS = idaapi.IWID_LOCALS
    """
    locals (35)
    """

    IWID_STKVIEW = idaapi.IWID_STKVIEW
    """
    stack view (36)
    """

    IWID_CHOOSER = idaapi.IWID_CHOOSER
    """
    chooser (37)
    """

    IWID_SHORTCUTCSR = idaapi.IWID_SHORTCUTCSR
    """
    shortcuts chooser (38)
    """

    IWID_SHORTCUTWIN = idaapi.IWID_SHORTCUTWIN
    """
    shortcuts window (39)
    """

    IWID_CPUREGS = idaapi.IWID_CPUREGS
    """
    registers (40)
    """

    IWID_SO_STRUCTS = idaapi.IWID_SO_STRUCTS
    """
    stroff (41)
    """

    IWID_SO_OFFSETS = idaapi.IWID_SO_OFFSETS
    """
    stroff (42)
    """

    IWID_CMDPALCSR = idaapi.IWID_CMDPALCSR
    """
    command palette (43)
    """

    IWID_CMDPALWIN = idaapi.IWID_CMDPALWIN
    """
    command palette (44)
    """

    IWID_SNIPPETS = idaapi.IWID_SNIPPETS
    """
    snippets (45)
    """

    IWID_CUSTVIEW = idaapi.IWID_CUSTVIEW
    """
    custom viewers (46)
    """

    IWID_ADDRWATCH = idaapi.IWID_ADDRWATCH
    """
    address watches (47)
    """

    IWID_PSEUDOCODE = idaapi.IWID_PSEUDOCODE
    """
    decompiler (48)
    """

    IWID_CALLS_CALLERS = idaapi.IWID_CALLS_CALLERS
    """
    funcalls, callers (49)
    """

    IWID_CALLS_CALLEES = idaapi.IWID_CALLS_CALLEES
    """
    funcalls, callees (50)
    """

    IWID_MDVIEWCSR = idaapi.IWID_MDVIEWCSR
    """
    lumina md view (51)
    """

    IWID_DISASM_ARROWS = idaapi.IWID_DISASM_ARROWS
    """
    arrows widget (52)
    """

    IWID_CV_LINE_INFOS = idaapi.IWID_CV_LINE_INFOS
    """
    lineinfo widget (53)
    """

    IWID_SRCPTHMAP_CSR = idaapi.IWID_SRCPTHMAP_CSR
    """
    mappings chooser (54)
    """

    IWID_SRCPTHUND_CSR = idaapi.IWID_SRCPTHUND_CSR
    """
    undesired chooser (55)
    """

    IWID_UNDOHIST = idaapi.IWID_UNDOHIST
    """
    Undo history (56)
    """

    IWID_SNIPPETS_CSR = idaapi.IWID_SNIPPETS_CSR
    """
    snippets chooser (57)
    """

    IWID_SCRIPTS_CSR = idaapi.IWID_SCRIPTS_CSR
    """
    recent scripts (58)
    """

    IWID_ALL = idaapi.IWID_ALL
    """
    mask
    """

    IWID_STACK = idaapi.IWID_STACK
    """
    Alias. Some IWID_* were confusing, and thus have been renamed. This is
    to ensure bw-compat.
    """

    IWID_DISASMS = idaapi.IWID_DISASMS

    IWID_DUMPS = idaapi.IWID_DUMPS

    IWID_SEARCHS = idaapi.IWID_SEARCHS


# --------------------------------------------------------------------------------------------------
# Widget


class Widget(object):
    def __init__(self):
        pass

    def current(self):
        current_widget = idaapi.get_current_widget()
        form_type = idaapi.get_widget_type(current_widget)
        vu = idaapi.get_widget_vdui(current_widget)
        if vu and form_type == Widgets.BWN_PSEUDOCODE:
            # HEXRAYS
            return vu
        elif form_type in Widgets:
            # IDA
            return form_type
        else:
            # PLUGIN OR MISC
            return Widgets.BWN_UNKNOWN
