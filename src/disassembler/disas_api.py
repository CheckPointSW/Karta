##################################################################################################################
## Note: This API is an indirection point, so we could (maybe) add support for more disassemblers in the future ##
##################################################################################################################

from collections    import defaultdict

class DisasAPI(object):
    """Abstract class that represents the required API from the disassembler layer.

    Attributes
    ----------
        _all_functions (list): list of all of the functions in the program - calculated once to avoid performance costs
        _all_strings (list): list of all of the strings in the program - calculated once to avoid performance costs
        _exported_symbols (list): list of all of the exported symbols names (as strings) - calculated once to avoid performance costs
    """

    def __init__(self):
        """Preform basic initialization."""
        self._all_functions     = None
        self._all_strings       = None
        self._exported_symbols  = None

    @staticmethod
    def logHandler():
        """Create a program specific logger handler, according to the logging.Handler API.

        Return Value:
            Created logger handler to be used throughout the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def functionsInner(self):
        """Create a collection / generator of all of the functions in the program (will be called only once).

        Return Value:
            collection of all of the functions in the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def stringsInner(self):
        """Create a collection / generator of all of the strings in the program (will be called only once).

        Note:
            A string object should have the following methods:
                str(str_obj) := string content
                str_obj.ea   := definition address (ea) of the string

        Return Value:
            sorted (by address) collection of all of the used strings in the program (as string objects)
        """
        raise NotImplementedError("Subclasses should implement this!")

    def exportsInner(self):
        """Create a collection / generator of all of the exported symbols (string names) in the program (will be called only once).

        Return Value:
            collection of all of the exported symbols in the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def functions(self):
        """Return a list of all of the functions in the binary (singleton style).

        Return Value:
            list of all of functions in the program
        """
        # singleton
        if self._all_functions is None:
            self._all_functions = list(self.functionsInner())

        # return the result
        return self._all_functions

    def strings(self):
        """Return a list of all of the string in the binary (singleton style).

        Note:
            A string object should have the following methods:
                str(str_obj) := string content
                str_obj.ea   := definition address (ea) of the string

        Return Value:
            sorted (by address) list of all of the used strings in the program (as string objects)
        """
        # singleton
        if self._all_strings is None:
            self._all_strings = list(self.stringsInner())

        # return the result
        return self._all_strings

    def exports(self):
        """Return a list of all of the exported symbols (string names) in the binary (singleton style).

        Return Value:
            list of all of the exported symbols in the program
        """
        # singleton
        if self._exported_symbols is None:
            self._exported_symbols = list(self.exportsInner())

        # return the result
        return self._exported_symbols

    def numSegments(self):
        """Return the number of the segments in the binary.

        Return Value:
            number of segments in the binary
        """
        raise NotImplementedError("Subclasses should implement this!")

    def segmentName(self, index):
        """Return the name of the wanted segment.

        Args:
            index (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            string name of the given segment
        """
        raise NotImplementedError("Subclasses should implement this!")

    def segmentFunctions(self, index):
        """Return a collection / generator of addresses (ea) of the functions in the given segment.

        Args:
            index (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            collection of function addresses
        """
        raise NotImplementedError("Subclasses should implement this!")

    def inputFile(self):
        """Return the (full) path of the input file that was used to create the database.

        Return Value:
            Path to the input file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def databaseFile(self):
        """Return the (full) path of the database file.

        Return Value:
            Path to the database file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def renameFunction(self, ea, name):
        """Rename the function at the specified address, using the supplied name.

        Args:
            ea (int): effective address of the wanted function
            name (str): new name for the function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def stringAt(self, ea):
        """Return the string that was found on the given address, regardless of it's type.

        Args:
            ea (int): effective address of the wanted string

        Return Value:
            A python string that contains the found string (or None on error)
        """
        raise NotImplementedError("Subclasses should implement this!")

    def nameAt(self, ea):
        """Return the name (if there is one) of the given address.

        Args:
            ea (int): wanted effective address

        Return Value:
            String name of the given address, or None if no such name exists
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcAt(self, ea):
        """Return the function that includes the given address.

        Args:
            ea (int): effective address of the wanted function

        Return Value:
            A function instance, or None if no such function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcName(self, func_ctx):
        """Return the name of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            String name of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcStart(self, func_ctx):
        """Return the start ea of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            start address (ea) of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcEnd(self, func_ctx):
        """Return the end ea of the function, using it's given context instance.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            end address (ea) of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcNameEA(self, func_ea):
        """Return the name of the function that was defined in the given address (including windows name fixes).

        Args:
            func_ea (int): effective address of the wanted function

        Return Value:
            The actual (wanted) name of the wanted function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def blocksAt(self, func_ctx):
        """Return a collection of basic blocks at the given function.

        Args:
            func_ctx (func): function instance (differs between implementations)

        Return Value:
            A collection of basic block instances
        """
        raise NotImplementedError("Subclasses should implement this!")

    def blockStart(self, block_ctx):
        """Return the start ea of the basic block, using it's given context instance.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            start address (ea) of the given basic block
        """
        raise NotImplementedError("Subclasses should implement this!")

    def blockFuncRefs(self, block_ctx):
        """Return pairs indicating function calls (or fptr refs) from the lines in the basic block instance.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            (ordered) list of tuples: [<address of function ref (src), referenced address of the function (dest)>, ]
        """
        raise NotImplementedError("Subclasses should implement this!")

    def nextBlocks(self, block_ctx):
        """Return a collection of potential next blocks in the flow graph.

        Args:
            block_ctx (block): basic block instance (differs between implementations)

        Return Value:
            collection of (probably 0-2) basic block successors
        """
        raise NotImplementedError("Subclasses should implement this!")

    def findImmediate(self, range_start, range_end, value):
        """Return all of the places (in the range) in which the immediate value was found.

        Args:
            range_start (int): ea of the range's start
            range_end (int): ea of the range's end
            value (int): value of the searched immediate

        Return Value:
            collection of ea's in which the value was found
        """
        raise NotImplementedError("Subclasses should implement this!")

    def drefsTo(self, ea):
        """Return a collection / generator of data references (eas) to the given address.

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have data references to our given address
        """
        raise NotImplementedError("Subclasses should implement this!")

    def crefsTo(self, ea):
        """Return a collection / generator of code references (eas) to the given address.

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have code references to our given address
        """
        raise NotImplementedError("Subclasses should implement this!")

    def exit(self):
        """Exit the disassembler (cleanly)."""
        raise NotImplementedError("Subclasses should implement this!")

    ############################
    ## Analysis Logic - Karta ##
    ############################

    def analyzeFunctionGraph(self, func_ea, src_mode):
        """Analyze the flow graph of a given function, generating a call-order mapping.

        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            A dictionary representing the the list of function calls that lead to a specific function call: call ==> list of preceding calls
        """
        block_to_ref   = defaultdict(set)
        ref_to_block   = {}
        ref_to_call    = {}
        block_to_reach = {}
        call_to_reach  = {}
        # 1st scan, build up the mapping - O(N) time, O(k) storage
        func = self.funcAt(func_ea)
        for block in self.blocksAt(func):
            block_to_reach[self.blockStart(block)] = set()
            for instr_pos, call_ea in self.blockFuncRefs(block):
                # record the call
                block_to_ref[self.blockStart(block)].add(instr_pos)
                ref_to_block[instr_pos] = block
                ref_to_call[instr_pos] = self.funcNameEA(call_ea) if src_mode else call_ea

        # 2nd scan, start from each reference, and propagate till the end - O(kN), E(N) time, O(N) storage
        sorted_refs = ref_to_block.keys()
        sorted_refs.sort()
        for ref in sorted_refs:
            start_block = ref_to_block[ref]
            block_ea = self.blockStart(start_block)
            working_set = set([ref])
            # we distinguish between refs even on the same block, no need to search for them because we scan using sorted_refs
            # mark the start block
            block_to_reach[block_ea].add(ref)
            # check if we can stop now
            if len(block_to_ref[block_ea]) > 1 and ref != max(block_to_ref[block_ea]):
                continue
            # carry on the tasks that were leftover by previous references
            working_set.update(block_to_reach[block_ea])
            # build a list of BFS nodes
            search_list = map(lambda x: (x, set(working_set)), self.nextBlocks(start_block))
            # Sanity hook around analysis problem in r2 - TODO: remove in the future
            search_list = filter(lambda x: self.blockStart(x[0]) in block_to_reach, search_list)
            seen_blocks = set()
            # BFS Scan - until the list is empty
            while len(search_list) > 0:
                new_search_list = []
                for cur_block, working_set in search_list:
                    cur_block_ea = self.blockStart(cur_block)
                    # check for loops
                    if cur_block_ea in seen_blocks and len(block_to_reach[cur_block_ea].difference(working_set)) == 0:
                        continue
                    # mark as seen
                    seen_blocks.add(cur_block_ea)
                    # always mark it
                    block_to_reach[cur_block_ea].update(working_set)
                    # if reached a starting block of an advanced reference, tell him to keep on for us
                    if cur_block_ea in block_to_ref and ref < max(block_to_ref[cur_block_ea]):
                        # we can stop :)
                        continue
                    # learn, and keep going
                    else:
                        working_set.update(block_to_reach[cur_block_ea])
                        new_search_list += map(lambda x: (x, set(working_set)), self.nextBlocks(cur_block))
                        # Sanity hook around analysis problem in r2 - TODO: remove in the future
                        new_search_list = filter(lambda x: self.blockStart(x[0]) in block_to_reach, new_search_list)
                search_list = new_search_list

        # 3rd scan, sum up the results - O(k) time, O(k*k) storage
        for ref in ref_to_block.keys():
            reffed_block_ea = self.blockStart(ref_to_block[ref])
            reachable_from = block_to_reach[reffed_block_ea]
            # add a filter to prevent collisions from the same block
            reachable_from = reachable_from.difference(filter(lambda x: x > ref, block_to_ref[reffed_block_ea]))
            if ref_to_call[ref] not in call_to_reach:
                call_to_reach[ref_to_call[ref]] = []
            current_record = set(filter(lambda x: x != ref_to_call[ref], map(lambda x: ref_to_call[x], reachable_from)))
            if current_record not in call_to_reach[ref_to_call[ref]]:
                call_to_reach[ref_to_call[ref]].append(list(current_record))

        return call_to_reach

    def analyzeFunction(self, func_ea, src_mode):
        """Analyze a given function, and creates a canonical representation for it.

        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            FunctionContext object representing the analyzed function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def searchIslands(self, func_ea, range_start, range_end):
        """Search a given function for "Islands" from a specific code range.

        Args:
            func_ea (int): effective address of the wanted function
            range_start (int): effective address of the start of the island range
            range_end (int): effective address of the end of the island range

        Return Value:
            Ordered list of code blocks for the found island, or None if found nothing
        """
        raise NotImplementedError("Subclasses should implement this!")

    def analyzeIslandFunction(self, blocks):
        """Analyze a given island function, and creates a canonical representation for it.

        Args:
            blocks (list): ordered list of code blocks (as returned from searchIslands())

        Return Value:
            IslandContext object representing the analyzed island
        """
        raise NotImplementedError("Subclasses should implement this!")

    def locateAnchorConsts(self, func_ea, const_set):
        """Analyze the function in search for specific immediate numerics.

        Args:
            func_ea (int): effective address of the analyzed function
            const_set (set): set of numeric consts to search for as immediate values

        Return Value :
            a set that contains the matched immediate value, an empty set if found none)
        """
        raise NotImplementedError("Subclasses should implement this!")

    def stringsInFunc(self, func_ea):
        """Analyze the function in search for all referenced strings.

        Args:
            func_ea (int): effective address of the analyzed function

        Return Value :
            a *list* that contains all of the referenced strings (including duplicates)
        """
        raise NotImplementedError("Subclasses should implement this!")

    ######################
    ## UI Functionality ##
    ######################

    def messageBox(self, text):
        """Pop a MessageBox to the user, with the given text. Blocks until closed.

        Note:
            This function contains some of Karta's UI logic

        Args:
            text (str): text to be written to the UI message box
        """
        raise NotImplementedError("Subclasses should implement this!")

    def configForm(self):
        """Pop open Karta's configuration form (for the matcher parameters).

        Note:
            This function contains some of Karta's UI logic

        Return Value :
            result dict iff the form was filled and "OK"ed, None otherwise
        """
        raise NotImplementedError("Subclasses should implement this!")

    def showMatchesForm(self, prepared_entries, suggested_names, rename_fn):
        """Pop open Karta's form presenting the matched library functions.

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
            suggested_names (dict): suggested names for the renaming: bin ea => name
            rename_fn (func): function handler for renaming the exported functions
        """
        raise NotImplementedError("Subclasses should implement this!")

    def showExternalsForm(self, prepared_entries):
        """Pop open Karta's form presenting the matched external functions.

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
        """
        raise NotImplementedError("Subclasses should implement this!")

class DisasCMD(object):
    """Abstract class that represents the required command-line API from the disassembler layer.

    Attributes
    ----------
        _path (path): command line path for the program
    """

    def __init__(self, path):
        """Preform the basic initialization.

        Args:
            path (path): command line path for the program
        """
        self._path = path

    @staticmethod
    def identify(path):
        """Check if the given command-line path refers to this disassembler.

        Args:
            path (str): command-line path to some disassembler (maybe for us)

        Return Value:
            True iff the command-line path refers to our program
        """
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    def name():
        """Get the program's name (used mainly for bug fixes in our code...).

        Return Value:
            String name of the disassembler program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def createDatabase(self, binary_file, is_windows):
        """Create a database file for the given binary file, compiled to windows or linux as specified.

        Args:
            binary_file (path): path to the input binary (*.o / *.obj) file
            is_windows (bool): True if this is a binary that was compiled for windows (*.obj), False otherwise (*.o)

        Return Value:
            path to the created database file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def executeScript(self, database, script):
        """Execute the given script over the given database file that was created earlier.

        Args:
            database (path): path to a database file created by the same program
            script (path): python script to be executed once the database is loaded
        """
        raise NotImplementedError("Subclasses should implement this!")
