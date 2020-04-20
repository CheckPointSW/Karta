# Dependencies that only exist inside IDA
import idautils
import idaapi
import idc
import ida_pro
import ida_search
import ida_nalt
# Dependencies with heavy setup
import sark
from .ida_analysis_api      import AnalyzerIDA
# Basic dependencies (only basic python packages)
from config.utils           import *
from disassembler.disas_api import DisasAPI
import logging

class IdaLogHandler(logging.Handler):
    """Integrate the log messages with IDA's output window."""

    def emit(self, record):
        """Emit a log record into IDA's output window.

        Args:
            record (LogRecord): a logging.LogRecord instance
        """
        idc.msg("%s\n" % (super(IdaLogHandler, self).format(record)))

class MessageBox(idaapi.Form):
    """Wrapper class that represents a GUI MessageBox.

    Note
    ----
        Contains specific (basic) Karta logic.
    """

    def __init__(self, text):
        """Create a basic message box.

        Args:
            text (str): Text to be shown by the message box
        """
        # dialog content
        dialog_content = """%s
                            %s
                          """ % (LIBRARY_NAME, text)
        idaapi.Form.__init__(self, dialog_content, {})

class ConfigForm(idaapi.Form):
    """Wrapper class that represents the GUI configuration form for Karta's scripts.

    Note
    ----
        Contains specific Karta logic.

    Attributes
    ----------
        _config_path (str): path to the chosen configuration directory (that includes the *.json files)
        _is_windows (bool): True iff the user specified this as a windows binary (False by default)
    """

    def __init__(self):
        """Create the starting configuration form."""
        # dialog content
        dialog_content = """%s
                            Please insert the path to configuration directory that holds the *.json files
                            to match against the current binary.

                            <#Select a *.json configs directory for %s exported libraries       #Configs Directory    :{_config_path}>
                            <#Enable this option for binaries compiled for Windows              #Is Windows binary    :{_is_windows}>{_check_group}>
                          """ % (LIBRARY_NAME, LIBRARY_NAME)
        # argument parsing
        args = {
                '_config_path': idaapi.Form.DirInput(swidth=65),
                '_check_group': idaapi.Form.ChkGroupControl(("_is_windows",)),
               }
        idaapi.Form.__init__(self, dialog_content, args)

class ChooseForm(idaapi.Choose):
    """Choose Form (view) implementation, responsible for showing and handling the matching results.

    Note
    ----
        Contains specific Karta logic.

    Attributes
    ----------
        _entries (list): (sorted) list of match results to be shown in the table
        _names (dict): suggested names for the match results: bin ea => name
        _selected (list): list of selected row indices
        _import_selected (cmd): GUI action handler responsible for importing the selected rows
        _import_matched (cmd): GUI action handler responsible for importing all of the matches
        _rename_handler (func): function handler for renaming the exported functions
    """

    def __init__(self, prepared_entries, suggested_names, rename_fn):
        """Construct the UI Form view, according to the matching entries.

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
            suggested_names (dict): suggested names for the renaming: bin ea => name
            rename_fn (func): function handler for renaming the exported functions
        """
        # Using tuples causes this to crash...
        columns = [['Line', 4], ['File Name', 20], ['Source Function Name', 25], ['Binary Address', 14], ['Binary Function Name', 25], ['Matching Rule \\ Information', 35]]
        idaapi.Choose.__init__(self, "%s Matching Results" % (libraryName()), columns, idaapi.Choose.CH_MULTI)
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

    # Overridden base function
    def OnClose(self):
        """Close the window - does nothing."""
        pass

    # Overridden base function
    def OnGetLine(self, n):
        """Retrieve a line from the form.

        Args:
            n (int): the desired input line

        Return Value:
            The selected line
        """
        return self.items[n]

    # Overridden base function
    def OnGetSize(self):
        """Return the number of items (rows) in the form.

        Return Value:
            number of rows in the table
        """
        return len(self.items)

    # Overridden base function
    def show(self):
        """Show the GUI of the form.

        Return Value:
            True iff successful
        """
        return self.Show(False) >= 0

    # Overridden base function
    def OnGetLineAttr(self, n):
        """Retrieve the line's attribute (color) from the form.

        Args:
            n (int): the desired input line

        Return Value:
            The selected line's attributes
        """
        return [self._entries[n][-1], 0]

    # Overridden base function
    def OnCommand(self, n, cmd_id):
        """Act upon the user's command.

        Args:
            n (int): unused
            cmd_id (int): ID for the requested command

        Return Value:
            Always returns True
        """
        imports = None
        # import (only) the selected functions
        if cmd_id == self._import_selected:
            imports = filter(lambda x: self._entries[x][4] in GUI_MATCH_REASONS, self._selected)
        # import all of the matched functions
        elif cmd_id == self._import_matched:
            imports = filter(lambda x: self._entries[x][4] in GUI_MATCH_REASONS, range(len(self.items)))
        # check if there is something to be done
        if imports is not None:
            self._rename_handler(list(map(lambda x: self._entries[x][2], imports)), self._names)
        # always return true
        return True

    # Overridden base function
    def OnSelectionChange(self, sel_list):
        """Update the list of selected rows.

        Args:
            sel_list (list): list of currently selected rows
        """
        self._selected = sel_list

class ExternalsChooseForm(idaapi.Choose):
    """Choose Form (view) implementation, responsible for showing and handling the external matching results.

    Note
    ----
        Contains specific Karta logic.

    Attributes
    ----------
        _entries (list): (sorted) list of match results to be shown in the table
    """

    def __init__(self, prepared_entries):
        """Construct the UI Form view, according to the external matching entries.

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
        """
        # Using tuples causes this to crash...
        columns = [['Line', 4], ['Source Function Name', 25], ['Binary Address', 14], ['Binary Function Name', 25], ['Matching Rule \\ Information', 35]]
        idaapi.Choose.__init__(self, "%s Matched Externals (LibC)" % (libraryName()), columns, idaapi.Choose.CH_MULTI)
        self.deflt = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self._entries  = prepared_entries
        # build the table
        for idx, entry in enumerate(prepared_entries):
            self.items.append(["%04d" % (idx + 1), entry[0], ("0x%08X" % (entry[1])) if entry[1] is not None else 'N/A', entry[2], entry[3]])

    # Overridden base function
    def OnClose(self):
        """Close the window - does nothing."""
        pass

    # Overridden base function
    def OnGetLine(self, n):
        """Retrieve a line from the form.

        Args:
            n (int): the desired input line

        Return Value:
            The selected line
        """
        return self.items[n]

    # Overridden base function
    def OnGetSize(self):
        """Return the number of items (rows) in the form.

        Return Value:
            number of rows in the table
        """
        return len(self.items)

    # Overridden base function
    def show(self):
        """Show the GUI of the form.

        Return Value:
            True iff successful
        """
        return self.Show(False) >= 0

    # Overridden base function
    def OnGetLineAttr(self, n):
        """Retrieve the line's attribute (color) from the form.

        Args:
            n (int): the desired input line (unused)

        Return Value:
            Always the same color: GUI_COLOR_GREEN
        """
        return [GUI_COLOR_GREEN, 0]

class IDA(DisasAPI):
    """DisasAPI implementation for the IDA disassembler, mainly based on the sark plugin.

    Attributes
    ----------
        _logic (analyzer): IDA Analyzer, containing the heart of Karta's canonical representation
    """

    def __init__(self):
        """Create the IDA adapter."""
        DisasAPI.__init__(self)
        self._logic = AnalyzerIDA(self)

    # Overridden base function
    @staticmethod
    def logHandler():
        """Create a program specific logger handler, according to the logging.Handler API.

        Return Value:
            Created logger handler to be used throughout the program
        """
        return IdaLogHandler()

    # Overridden base function
    def functionsInner(self):
        """Create a collection / generator of all of the functions in the program (will be called only once).

        Return Value:
            collection of all of the functions in the program
        """
        return idautils.Functions()

    # Overridden base function
    def stringsInner(self):
        """Create a collection / generator of all of the strings in the program (will be called only once).

        Note:
            A string object should have the following methods:
                str(str_obj) := string content
                str_obj.ea   := definition address (ea) of the string

        Return Value:
            sorted (by address) collection of all of the used strings in the program (as string objects)
        """
        return idautils.Strings()

    # Overridden base function
    def exportsInner(self):
        """Create a collection / generator of all of the exported symbols (string names) in the program (will be called only once).

        Return Value:
            collection of all of the exported symbols in the program
        """
        return list(map(lambda x: self._logic.funcNameInner(x[-1]), idautils.Entries()))

    # Overridden base function
    def numSegments(self):
        """Return the number of the segments in the binary.

        Return Value:
            number of segments in the binary
        """
        return len(list(idautils.Segments()))

    # Overridden base function
    def segmentName(self, idx):
        """Return the name of the wanted segment.

        Args:
            idx (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            string name of the given segment
        """
        return sark.Segment(index=idx).name

    # Overridden base function
    def segmentFunctions(self, idx):
        """Return a collection / generator of addresses (ea) of the functions in the given segment.

        Args:
            idx (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            collection of function addresses
        """
        return list(map(lambda x: x.ea, sark.Segment(index=idx).functions))

    # Overridden base function
    def inputFile(self):
        """Return the (full) path of the input file that was used to create the database.

        Return Value:
            Path to the input file
        """
        return ida_nalt.get_root_filename()

    # Overridden base function
    def databaseFile(self):
        """Return the (full) path of the database file.

        Return Value:
            Path to the database file
        """
        return idc.get_idb_path()

    # Overridden base function
    def renameFunction(self, ea, name):
        """Rename the function at the specified address, using the supplied name.

        Args:
            ea (int): effective address of the wanted function
            name (str): new name for the function
        """
        idc.set_name(ea, name, idc.SN_CHECK)

    # Overridden base function
    def stringAt(self, ea):
        """Return the string that was found on the given address, regardless of it's type.

        Args:
            ea (int): effective address of the wanted string

        Return Value:
            A python string that contains the found string (or None on error)
        """
        str_type = idc.get_str_type(ea)
        if str_type is None:
            return None
        return idc.get_strlit_contents(ea, -1, str_type).decode("utf-8")

    # Overridden base function
    def nameAt(self, ea):
        """Return the name (if there is one) of the given address.

        Args:
            ea (int): wanted effective address

        Return Value:
            String name of the given address, or None if no such name exists
        """
        return self._logic.funcNameInner(sark.Line(ea).name)

    # Overridden base function
    def funcAt(self, ea):
        """Return the function that includes the given address.

        Args:
            ea (int): effective address of the wanted function

        Return Value:
            A function instance, or None if no such function
        """
        func = idaapi.get_func(ea)
        if func is None:
            return None
        # can now use sark more freely
        try:
            return sark.Function(ea)
        except sark.exceptions.SarkNoFunction:
            # just to be sure
            return None

    # Overridden base function
    def funcName(self, func_ctx):
        """Return the name of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            String name of the given function
        """
        return self._logic.funcNameInner(func_ctx.name)

    # Overridden base function
    def funcStart(self, func_ctx):
        """Return the start ea of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            start address (ea) of the given function
        """
        return func_ctx.start_ea

    # Overridden base function
    def funcEnd(self, func_ctx):
        """Return the end ea of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            end address (ea) of the given function
        """
        return func_ctx.end_ea

    # Overridden base function
    def funcNameEA(self, func_ea):
        """Return the name of the function that was defined in the given address (including windows name fixes).

        Args:
            func_ea (int): effective address of the wanted function

        Return Value:
            The actual (wanted) name of the wanted function
        """
        return self._logic.funcNameEA(func_ea)

    # Overridden base function
    def blocksAt(self, func_ctx):
        """Return a collection of basic blocks at the given function.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            A collection of basic block instances
        """
        return idaapi.FlowChart(func_ctx.func_t)

    # Overridden base function
    def blockStart(self, block_ctx):
        """Return the start ea of the basic block, using it's given context instance.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            start address (ea) of the given basic block
        """
        return block_ctx.start_ea

    # Overridden base function
    def blockFuncRefs(self, block_ctx):
        """Return pairs indicating function calls (or fptr refs) from the lines in the basic block instance.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            (ordered) list of tuples: [<address of function ref (src), referenced address of the function (dest)>, ]
        """
        return self._logic.analyzeFunctionBlock(block_ctx.start_ea)

    # Overridden base function
    def nextBlocks(self, block_ctx):
        """Return a collection of potential next blocks in the flow graph.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            collection of (probably 0-2) basic block successors
        """
        return block_ctx.succs()

    # Overridden base function
    def findImmediate(self, range_start, range_end, value):
        """Return all of the places (in the range) in which the immediate value was found.

        Args:
            range_start (int): ea of the range's start
            range_end (int): ea of the range's end
            value (int): value of the searched immediate

        Return Value:
            collection of ea's in which the value was found
        """
        search_pos = range_start
        while search_pos < range_end:
            match_ea, garbage = ida_search.find_imm(search_pos, idc.SEARCH_DOWN, value)
            search_pos = match_ea + 1
            # Filter out mismatches
            if match_ea == idc.BADADDR:
                break
            # return the correct result to the caller
            yield match_ea

    # Overridden base function
    def drefsTo(self, ea):
        """Return a collection / generator of data references (eas) to the given address.

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have data references to our given address
        """
        return sark.Line(ea).drefs_to

    # Overridden base function
    def crefsTo(self, ea):
        """Return a collection / generator of code references (eas) to the given address.

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have code references to our given address
        """
        return sark.Line(ea).crefs_to

    # Overridden base function
    def exit(self):
        """Exit the disassembler (cleanly)."""
        ida_pro.qexit(0)

    ############################
    ## Analysis Logic - Karta ##
    ############################

    # Overridden base function
    def analyzeFunction(self, func_ea, src_mode):
        """Analyze a given function, and creates a canonical representation for it.

        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            FunctionContext object representing the analyzed function
        """
        return self._logic.analyzeFunction(func_ea, src_mode)

    # Overridden base function
    def searchIslands(self, func_ea, range_start, range_end):
        """Search a given function for "Islands" from a specific code range.

        Args:
            func_ea (int): effective address of the wanted function
            range_start (int): effective address of the start of the island range
            range_end (int): effective address of the end of the island range

        Return Value:
            Ordered list of code blocks for the found island, or None if found nothing
        """
        return self._logic.searchIslands(func_ea, range_start, range_end)

    # Overridden base function
    def analyzeIslandFunction(self, blocks):
        """Analyze a given island function, and creates a canonical representation for it.

        Args:
            blocks (list): ordered list of code blocks (as returned from searchIslands())

        Return Value:
            IslandContext object representing the analyzed island
        """
        return self._logic.analyzeIslandFunction(blocks)

    # Overridden base function
    def locateAnchorConsts(self, func_ea, const_set):
        """Analyze the function in search for specific immediate numerics.

        Args:
            func_ea (int): effective address of the analyzed function
            const_set (set): set of numeric consts to search for as immediate values

        Return Value:
            a set that contains the matched immediate value, an empty set if found none)
        """
        return self._logic.locateAnchorConsts(func_ea, const_set)

    # Overridden base function
    def stringsInFunc(self, func_ea):
        """Analyze the function in search for all referenced strings.

        Args:
            func_ea (int): effective address of the analyzed function

        Return Value :
            a *list* that contains all of the referenced strings (including duplicates)
        """
        return self._logic.stringsInFunc(func_ea)

    ######################
    ## UI Functionality ##
    ######################

    # Overridden base function
    def messageBox(self, text):
        """Pop a MessageBox to the user, with the given text. Blocks until closed.

        Note:
            This function contains some of Karta's UI logic

        Args:
            text (str): text to be written to the UI message box
        """
        m = MessageBox(text)
        m.Compile()
        m.Execute()

    # Overridden base function
    def configForm(self):
        """Pop open Karta's configuration form (for the matcher parameters).

        Note:
            This function contains some of Karta's UI logic

        Return Value:
            result dict iff the form was filled and "OK"ed, None otherwise
        """
        c = ConfigForm()
        c.Compile()
        if not c.Execute():
            return None
        # return the values to the caller
        config_values = {
                         "config_path": c._config_path.value,
                         "is_windows":  c._is_windows.checked,
                        }
        return config_values

    # Overridden base function
    def showMatchesForm(self, prepared_entries, bin_suggested_names, rename_fn):
        """Pop open Karta's form presenting the matched library functions.

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
            suggested_names (dict): suggested names for the renaming: bin ea => name
            rename_fn (func): function handler for renaming the exported functions
        """
        view = ChooseForm(prepared_entries, bin_suggested_names, rename_fn)
        view.show()

    # Overridden base function
    def showExternalsForm(self, prepared_entries):
        """Pop open Karta's form presenting the matched external functions.

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
        """
        view = ExternalsChooseForm(prepared_entries)
        view.show()
