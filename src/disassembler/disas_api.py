##################################################################################################################
## Note: This API is an indirection point, so we could (maybe) add support for more disassemblers in the future ##
##################################################################################################################

class DisasAPI(object):
    """Abstract class that represents the required API from the disassembler layer

    Attributes:
        _all_functions (list): list of all of the funcitons in the program - calculated once to avoid performance costs
        _all_strings (list): list of all of the strings in the program - calculated once to avoid performance costs
        _exported_symbols (list): list of all of the exported symbols names (as strings) - calculated once to avoid performance costs
    """
    def __init__(self):
        """Basic Ctor for the base class, performs the basic initializations"""
        self._all_functions = None
        self._all_strings = None
        self._exported_symbols = None

    @staticmethod
    def logHandler():
        """Creates a program specific logger handler, according to the logging.Handler API

        Return Value:
            Created logger handler to be used throught the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def functionsInner(self):
        """Creates a collection / generator of all of the functions in the program (will be called only once)

        Return Value:
            collection of all of the functions in the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def stringsInner(self):
        """Creates a collection / generator of all of the strings in the program (will be called only once)

        Return Value:
            collection of all of the used strings in the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def exportsInner(self):
        """Creates a collection / generator of all of the exported symbols (string names) in the program (will be called only once)

        Return Value:
            collection of all of the exported symbols in the program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def functions(self):
        """Returns a list of all of the functions in the binary (singleton style)

        Return Value:
            list of all of functions in the program
        """
        # singleton
        if self._all_functions is None:
            self._all_functions = list(self.functionsInner())

        # return the result
        return self._all_functions

    def strings(self):
        """Returns a list of all of the string in the binary (singleton style)

        Note:
            A string object should have the following methods:
                str(str_obj) := string content
                str_obj.ea   := definition address (ea) of the string

        Return Value:
            list of all of the used strings in the program (as string objects)
        """
        # singleton
        if self._all_strings is None:
            self._all_strings = list(self.stringsInner())

        # return the result
        return self._all_strings

    def exports(self):
        """Returns a list of all of the exported symbols (string names) in the binary (singleton style)

        Return Value:
            list of all of the exported symbols in the program
        """
        # singleton
        if self._exported_symbols is None:
            self._exported_symbols = list(self.exportsInner())

        # return the result
        return self._exported_symbols

    def numSegments(self):
        """Returns the number of the segments in the binary

        Return Value:
            number of segments in the binary
        """
        raise NotImplementedError("Subclasses should implement this!")

    def segmentName(self, index):
        """Returns the name of the wanted segment

        Args:
            index (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            string name of the given segment
        """
        raise NotImplementedError("Subclasses should implement this!")

    def segmentFunctions(self, index):
        """Returns a collection / generator of addresses (ea) of the functions in the given segment

        Args:
            index (int): segment index (in the range [0, numSegments() - 1])

        Return Value:
            collection of function addresses
        """
        raise NotImplementedError("Subclasses should implement this!")

    def inputFile(self):
        """Returns the (full) path of the input file that was used to create the database

        Return Value:
            Path to the input file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def databaseFile(self):
        """Returns the (full) path of the database file

        Return Value:
            Path to the database file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def renameFunction(self, ea, name):
        """Renames the function at the specified address, using the supplied name

        Args:
            ea (int): effective address of the wanted function
            name (str): new name for the function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def stringAt(self, ea):
        """Returns the string that was found on the given address, regardless of it's type

        Args:
            ea (int): effective address of the wanted string

        Return Value:
            A python string that contains the found string (or None on error)
        """
        raise NotImplementedError("Subclasses should implement this!")

    def nameAt(self, ea):
        """Returns the name (if there is one) of the given address

        Args:
            ea (int): wanted effective address

        Return Value:
            String name of the given address, or None if no such name exists
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcAt(self, ea):
        """Returns the function that includes the given address

        Args:
            ea (int): effective address of the wanted function

        Return Value:
            A function instance, or None if no such function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcName(self, func_ctx):
        """Returns the name of the function, using it's given context instance

        Args:
            func_ctx (func): funciton instance (differs between implementations)

        Return Value:
            String name of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcStart(self, func_ctx):
        """Returns the start ea of the function, using it's given context instance

        Args:
            func_ctx (func): funciton instance (differs between implementations)

        Return Value:
            start address (ea) of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def funcEnd(self, func_ctx):
        """Returns the end ea of the function, using it's given context instance

        Args:
            func_ctx (func): funciton instance (differs between implementations)

        Return Value:
            end address (ea) of the given function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def findImmediate(self, range_start, range_end, value):
        """Returns all of the places (in the range) in which the immediate value was found

        Args:
            range_start (int): ea of the range's start
            range_end (int): ea of the rang's end
            value (int): value of the searched immediate

        Return Value:
            collection of ea's in which the value was found
        """
        raise NotImplementedError("Subclasses should implement this!")

    def drefsTo(self, ea):
        """Returns a collection / generator of data references (eas) to the given address

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have data references to our given address
        """
        raise NotImplementedError("Subclasses should implement this!")

    def crefsTo(self, ea):
        """Returns a collection / generator of code references (eas) to the given address

        Args:
            ea (int): wanted ea

        Return Value:
            collection of ea's that have code references to our given address
        """
        raise NotImplementedError("Subclasses should implement this!")

    def exit(self):
        """Exits the disassembler (cleanly)"""
        raise NotImplementedError("Subclasses should implement this!")

    ############################
    ## Analysis Logic - Karta ##
    ############################

    def funcNameEA(self, func_ea):
        """Returns the name of the function that was defined in the given address (including windows name fixes)
        
        Args:
            func_ea (int): effective address of the wanted function

        Return Value:
            The actual (wanted) name of the wanted function
        """
        func = self.funcAt(func_ea)
        if func is not None:
            return self.funcName(func)
        return self.logic.funcNameInner(self.nameAt(func_ea))

    def analyzeFunctionGraph(self, func_ea, src_mode) :
        """Analyzes the flow graph of a given function, generating a call-order mapping
        
        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            A dictionary representing the the list of function calls that lead to a specific function call: call ==> list of preceding calls
        """
        raise NotImplementedError("Subclasses should implement this!")

    def analyzeFunction(self, func_ea, src_mode) :
        """Analyze a given function, and creates a canonical representation for it
        
        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            FunctionContext object representing the analyzed function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def searchIslands(self, func_ea, range_start, range_end) :
        """Search a given function for "Islands" from a specific code range
        
        Args:
            func_ea (int): effective address of the wanted function
            range_start (int): effective address of the start of the island range
            range_end (int): effective address of the end of the island range

        Return Value:
            Orderred list of code blocks for the found island, or None if found nothing
        """
        raise NotImplementedError("Subclasses should implement this!")

    def analyzeIslandFunction(self, blocks) :
        """Analyze a given island function, and creates a canonical representation for it
        
        Args:
            blocks (list): orderred list of code blocks (as returned from searchIslands())

        Return Value:
            IslandContext object representing the analyzed island
        """
        raise NotImplementedError("Subclasses should implement this!")

    def locateAnchorConsts(self, func_ea, const_set) :
        """Analyzes the function in search for specific immediate numerics

        Args:
            func_ea (int): effective address of the analyzed function
            const_set (set): set of numeric consts to search for as immediate values
        
        Return Value :
            a set that contains the matched immediate value, an empty set if found none)
        """
        raise NotImplementedError("Subclasses should implement this!")

    ######################
    ## UI Functionality ##
    ######################

    def messageBox(self, text):
        """Pops a MessageBox to the user, with the given text. Blocks untill closed

        Note:
            This function contains some of Karta's UI logic

        Args:
            text (str): text to be written to the UI message box
        """
        raise NotImplementedError("Subclasses should implement this!")

    def configForm(self):
        """Pops open Karta's configuration form (for the matcher parameters)

        Note:
            This function contains some of Karta's UI logic

        Return Value :
            result dict iff the form was filled and "OK"ed, None otherwise
        """
        raise NotImplementedError("Subclasses should implement this!")

    def showMatchesForm(self, prepared_entries, suggested_names, rename_fn):
        """Pops open Karta's form presenting the matched library functions

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
            suggested_names (dict): suggested names for the renaming: bin ea => name
            rename_fn (func): function handler for renaming the exported functions
        """
        raise NotImplementedError("Subclasses should implement this!")

    def showExternalsForm(self, prepared_entries):
        """Pops open Karta's form presenting the matched external functions

        Note:
            This function contains some of Karta's UI logic

        Args:
            prepared_entries (list): list of UI rows, including the length for the different columns
        """
        raise NotImplementedError("Subclasses should implement this!")

class DisasCMD(object):
    """Abstract class that represents the required command-line API from the disassembler layer

    Attributes:
        _path (path): command line path for the program
    """
    def __init__(self, path):
        """Basic Ctor for the base class, performs the basic initializations
        
        Args:
            path (path): command line path for the program
        """
        self._path = path

    @staticmethod
    def identify(path):
        """Checks if the given command-line path refers to this disassembler

        Args:
            path (str): command-line path to some disassembler (maybe for us)

        Return Value:
            True iff the command-line path refers to our program
        """
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    def name():
        """Returns the program's name (used mainly for bug fixes in our code...)

        Return Value:
            String name of the disassembler program
        """
        raise NotImplementedError("Subclasses should implement this!")

    def createDatabase(self, binary_file, is_windows):
        """Creates a database file for the given binary file, compiled to windows or linux as specified

        Args:
            binary_file (path): path to the input binary (*.o / *.obj) file
            is_windows (bool): True if this is a binary that was compiled for windows (*.obj), False otherwise (*.o)

        Return Value:
            path to the created database file
        """
        raise NotImplementedError("Subclasses should implement this!")

    def executeScript(self, database, script):
        """Executes the given script over the given database file that was created earlier

        Args:
            database (path): path to a database file created by the same program
            script (path): python script to be executed once the database is loaded
        """
        raise NotImplementedError("Subclasses should implement this!")