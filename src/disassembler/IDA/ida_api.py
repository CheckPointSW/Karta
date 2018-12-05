import idautils
import idaapi
import idc
import sark
from config.utils           import *
from disassembler.disas_api import DisasAPI
from disassembler.factory   import registerDisassembler
from ida_analysis_api       import AnalyzerIDA
import logging

class IdaLogHandler(logging.Handler) :
    """Integrates the log messages with IDA's output window"""
    def emit(self, record) :
        idc.Message("%s\n" % (super(IdaLogHandler, self).format(record)))

class MessageBox(idaapi.Form):
    """Wrapper class that represents a GUI MessageBox

    Note:
        Contains specific (basic) Karta logic.
    """
    def __init__(self, text):
        """Basic Ctor for the class

        Args:
            text (str): Text to be shown by the message box
        """
        # dialog content
        dialog_content = """%s
                            %s
                          """ % (LIBRARY_NAME, text)
        idaapi.Form.__init__(self, dialog_content, {})

class ConfigForm(idaapi.Form):
    """Wrapper class that represents the GUI configuration form for Karta's scripts

    Note:
        Contains specific Karta logic.

    Attributes:
        _config_path (str): path to the chosen configuration directory (that includes the *.json files)
        _is_windows (bool): True iff the user specified this as a windows binary (False by default)
    """
    def __init__(self):
        """Basic Ctor for the Form class"""
        # dialog content
        dialog_content = """%s
                            Please insert the path to configuration directory that holds the *.json files
                            to match against the current binary.

                            <#Select a *.json configs directory for %s exported libraries       #Configs Directory    :{_config_path}>
                            <#Enable this option for binaries compiled for Windows              #Is Windows binary    :{_is_windows}>{_check_group}>
                          """ % (LIBRARY_NAME, LIBRARY_NAME)
        # argument parsing
        args = {'_config_path'       : idaapi.Form.DirInput(swidth=65),
                '_check_group'       : idaapi.Form.ChkGroupControl(("_is_windows",)),
                }
        idaapi.Form.__init__(self, dialog_content, args)

class ChooseForm(idaapi.Choose2):
    """Choose Form (view) implementation, responsible for showing and handling the matching results

    Note:
        Contains specific Karta logic.

    Attributes:
        _entries (list): (sorted) list of match results to be shown in the table
        _names (dict): suggested names for the match results: bin ea => name
        _selected (list): list of selected row indices
        _import_selected (cmd): GUI action handler responsible for importing the selected rows
        _import_matched (cmd): GUI action handler responsible for importing all of the matches
        _rename_handler (func): function handler for renaming the exported functions
    """
    def __init__(self, prepared_entries, suggested_names, rename_fn):
        """Constructs the UI Form view, according to the matching entries

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
            suggested_names (dict): suggested names for the renaming: bin ea => name
            rename_fn (func): function handler for renaming the exported functions
        """
        # Using tuples causes this to crash...
        columns = [['Line', 4], ['File Name', 20], ['Source Function Name', 25], ['Binary Address', 14], ['Binary Function Name', 25], ['Matching Rule \ Information', 35]]
        idaapi.Choose2.__init__(self, "%s Matching Results" % (libraryName()), columns, idaapi.Choose2.CH_MULTI)
        self.deflt = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self._entries  = prepared_entries
        self._names    = suggested_names
        self._selected = []
        # build the table
        for idx, entry in enumerate(prepared_entries):
            self.items.append(["%04d" % (idx + 1), entry[0], entry[1], ("0x%08X" % (entry[2])) if entry[2] is not None else 'N/A', entry[3], entry[4]])
        # register additional command handlers
        self._import_selected = self.AddCommand(GUI_CMD_IMPORT_SELECTED)
        self._import_matched  = self.AddCommand(GUI_CMD_IMPORT_MATCHED)
        self._rename_handler  = rename_fn

    # Overriden base function
    def OnClose(self):
        pass

    # Overriden base function
    def OnGetLine(self, n):
        return self.items[n]

    # Overriden base function
    def OnGetSize(self):
        return len(self.items)

    # Overriden base function
    def show(self):
        return self.Show(False) >= 0

    # Overriden base function
    def OnGetLineAttr(self, n):
        return [self._entries[n][-1], 0]

    # Overriden base function
    def OnCommand(self, n, cmd_id):
        imports = None
        # import (only) the selected functions
        if cmd_id == self._import_selected:
            imports = filter(lambda x : self._entries[x][4] in GUI_MATCH_REASONS, self._selected)
        # import all of the matched functions
        elif cmd_id == self._import_matched:
            imports = filter(lambda x : self._entries[x][4] in GUI_MATCH_REASONS, xrange(len(self.items)))
        # check if there is something to be done
        if imports is not None:
            self._rename_handler(map(lambda x : self._entries[x][2], imports), self._names)
        # always return true
        return True

    # Overriden base function
    def OnSelectionChange(self,  sel_list):
        self._selected = sel_list

class ExternalsChooseForm(idaapi.Choose2):
    """Choose Form (view) implementation, responsible for showing and handling the external matching results

    Note:
        Contains specific Karta logic.

    Attributes:
        _entries (list): (sorted) list of match results to be shown in the table
    """
    def __init__(self, prepared_entries):
        """Constructs the UI Form view, according to the external matching entries

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
        """
        # Using tuples causes this to crash...
        columns = [['Line', 4], ['Source Function Name', 25], ['Binary Address', 14], ['Binary Function Name', 25], ['Matching Rule \ Information', 35]]
        idaapi.Choose2.__init__(self, "%s Matched Externals (LibC)" % (libraryName()), columns, idaapi.Choose2.CH_MULTI)
        self.deflt = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self._entries  = prepared_entries
        # build the table
        for idx, entry in enumerate(prepared_entries):
            self.items.append(["%04d" % (idx + 1), entry[0], ("0x%08X" % (entry[1])) if entry[1] is not None else 'N/A', entry[2], entry[3]])

    # Overriden base function
    def OnClose(self):
        pass

    # Overriden base function
    def OnGetLine(self, n):
        return self.items[n]

    # Overriden base function
    def OnGetSize(self):
        return len(self.items)

    # Overriden base function
    def show(self):
        return self.Show(False) >= 0

    # Overriden base function
    def OnGetLineAttr(self, n):
        return [GUI_COLOR_GREEN, 0]

class IDA(DisasAPI):
    """DisasAPI implementation for the IDA disassembler, mainly based on the sark plugin

    Attributes:
        _logic (analyzer): IDA Analyzer, containg the heart of Karta's canonical representation
    """

    def __init__(self):
        DisasAPI.__init__(self)
        self._logic = AnalyzerIDA(self)

    # Overriden base function
    @staticmethod
    def logHandler():
        return IdaLogHandler()

    # Overriden base function
    def functionsInner(self):
        return idautils.Functions()

    # Overriden base function
    def stringsInner(self):
        return idautils.Strings()

    # Overriden base function
    def exportsInner(self):
        return map(lambda x : x[-1], idautils.Entries())

    # Overriden base function
    def numSegments(self):
        return len(list(idautils.Segments()))

    # Overriden base function
    def segmentName(self, index):
        return sark.Segment(index = index).name

    # Overriden base function
    def segmentFunctions(self, index):
        return map(lambda x : x.ea, sark.Segment(index = index).functions)

    # Overriden base function
    def inputFile(self):
        return idc.GetInputFile()

    # Overriden base function
    def databaseFile(self):
        return idc.GetIdbPath()

    # Overriden base function
    def renameFunction(self, ea, name):
        idc.MakeName(ea, name.encode("ascii"))

    # Overriden base function
    def stringAt(self, ea):
        str_type = idc.GetStringType(ea)
        if str_type is None:
            return None
        return idc.GetString(ea, -1, str_type)

    # Overriden base function
    def nameAt(self, ea):
        return self._logic.funcNameInner(sark.Line(ea).name)

    # Overriden base function
    def funcAt(self, ea):
        func = idaapi.get_func(ea)
        if func is None :
            return None
        # can now use sark more freely
        try:
            return sark.Function(ea)
        except:
            # just to be sure
            return None

    # Overriden base function
    def funcName(self, func_ctx):
        return self._logic.funcNameInner(func_ctx.name)

    # Overriden base function
    def funcStart(self, func_ctx):
        return func_ctx.startEA

    # Overriden base function
    def funcEnd(self, func_ctx):
        return func_ctx.endEA

    # Overriden base function
    def findImmediate(self, range_start, range_end, value):
        search_pos = range_start
        while search_pos < range_end :
            match_ea, garbage = idc.FindImmediate(search_pos, idc.SEARCH_DOWN, value)
            search_pos = match_ea + 1
            # Filter out mismatches
            if match_ea == idc.BADADDR :
                break
            # return the correct result to the caller
            yield match_ea

    # Overriden base function
    def drefsTo(self, ea):
        return sark.Line(ea).drefs_to

    # Overriden base function
    def crefsTo(self, ea):
        return sark.Line(ea).crefs_to

    # Overriden base function
    def exit(self):
        idc.Exit(0)

    ############################
    ## Analysis Logic - Karta ##
    ############################

    # Overriden base function
    def analyzeFunctionGraph(self, func_ea, src_mode) :
        return self._logic.analyzeFunctionGraph(func_ea, src_mode)

    # Overriden base function
    def analyzeFunction(self, func_ea, src_mode) :
        return self._logic.analyzeFunction(func_ea, src_mode)

    # Overriden base function
    def searchIslands(self, func_ea, range_start, range_end) :
        return self._logic.searchIslands(func_ea, range_start, range_end)

    # Overriden base function
    def analyzeIslandFunction(self, blocks) :
        return self._logic.analyzeIslandFunction(blocks)

    # Overriden base function
    def locateAnchorConsts(self, func_ea, const_set) :
        return self._logic.locateAnchorConsts(func_ea, const_set)

    ######################
    ## UI Functionality ##
    ######################

    # Overriden base function
    def messageBox(self, text):
        m = MessageBox(text)
        m.Compile()
        m.Execute()

    # Overriden base function
    def configForm(self):
        c = ConfigForm()
        c.Compile()
        if not c.Execute():
            return None
        # return the values to the caller
        config_values = {"config_path" : c._config_path.value,
                         "is_windows"  : c._is_windows.checked,
                        }
        return config_values

    # Overriden base function
    def showMatchesForm(self, prepared_entries, bin_suggested_names, rename_fn):
        view = ChooseForm(prepared_entries, bin_suggested_names, rename_fn)
        view.show()

    # Overriden base function
    def showExternalsForm(self, prepared_entries):
        view = ExternalsChooseForm(prepared_entries)
        view.show()

# Don't forget to register at the factory
registerDisassembler("IDA", IDA)
