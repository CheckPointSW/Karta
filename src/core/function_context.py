class CodeContext(object):
    """Abstract class that represents a code chunk's canonical representation.

    Attributes
    ----------
        name (str): name of the code chunk (function/location)
        match (differs): matched context (could be ea for externals or a src/bin contexts for bin/src function)
    """

    def __init__(self, name):
        """Create the basic instance.

        Args:
            name (str): name of the code chunk (function/location)
        """
        self.name   = name
        self.match  = None

    def matched(self):
        """Check if the code context was matched with src/bin counterpart.

        Return Value:
            True iff the context was matched
        """
        return self.match is not None

    def declareMatch(self, match):
        """Declare a match between a source and a bin context.

        Args:
            match (varies): the match context/ea
        """
        raise NotImplementedError("Subclasses should implement this!")

    def valid(self):
        """Check if the function is still valid (still active).

        Return Value:
            True iff the function still exists in the file matching process
        """
        raise NotImplementedError("Subclasses should implement this!")

    def active(self):
        """Check if the given function is still in the matching game.

        Return Value:
            True iff the function is valid and wasn't matched yet
        """
        return self.valid() and not self.matched()

class MappedCodeContext(CodeContext):
    """A context that describes a binary function / source function that is part of an indexed array of functions.

    Attributes
    ----------
        index (int): index of the function in the global array of all source / binary functions
    """

    def __init__(self, name, index):
        """Create the basic instance.

        Args:
            name (str): temporary (?) name given by the disassembler
            index (int): index of the function in the global array of all source / binary functions
        """
        super(MappedCodeContext, self).__init__(name)
        self.index = index

class BinaryCodeContext(MappedCodeContext):
    """A context that describes a binary function / code snippet (an island).

    Attributes
    ----------
        ea (int): effective address of the given binary function
    """

    def __init__(self, ea, name, index):
        """Create the basic instance.

        Args:
            ea (int): effective address of the binary function
            name (str): temporary (?) name given by the disassembler
            index (int): index of the function in the global array of all source / binary functions
        """
        super(BinaryCodeContext, self).__init__(name, index)
        self.ea = ea

    def isPartial(self):
        """Tell us if the current instance is a full function, or only a partial one (an island).

        Return Value:
            True iff a partial function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def preprocess(self):
        """Preform preprocess calculations once here after initialization, to avoid performance costs later."""
        raise NotImplementedError("Subclasses should implement this!")

class SourceCodeContext(MappedCodeContext):
    """A context that describes a source function."""

    def disable(self):
        """Mark the source function as absent (inlined / ifdeffed out)."""
        raise NotImplementedError("Subclasses should implement this!")

class SrcFileFunction(MappedCodeContext):
    """A contex tthat describes a source function, and couples it with it's containing file.

    Attributes
    ----------
        file (FileMatch): FileMatch instance representing our source file
    """

    def __init__(self, name, index):
        """Create the basic instance.

        Args:
            name (str): source function name
            index (int): index of the function in the global array of all source functions
        """
        super(SrcFileFunction, self).__init__(name, index)
        self.file = None

    def linkFile(self, file_match):
        """Link our source function to it's newly created file data structure.

        Args:
            file (FileMatch): FileMatch instance representing our source file
        """
        self.file = file_match

class BinFileFunction(BinaryCodeContext):
    """A context that describes a binary function, that tries to locate the source file it should be placed in.

    Attributes
    ----------
        file (FileMatch): actual FileMatch instance representing our (located) source file
        files (set): set of candidate FileMatch instances, representing the possible files for our function
    """

    def __init__(self, ea, name, index):
        """Create the basic instance.

        Args:
            ea (int): effective address of the given code chunk
            name (str): temporary (?) name given by the disassembler
            index (int): index of the function in the global array of all binary functions
        """
        super(BinFileFunction, self).__init__(ea, name, index)
        self.file  = None
        self.files = set()

    def selfCheck(self):
        """Propagate the newly learned information about our file to our internal data structures."""
        raise NotImplementedError("Subclasses should implement this!")

    def linkFile(self, file_match):
        """Link our context to a code file (FileMatch instance).

        Note:
            * 1st invocation: adds the given source file as a potential candidate
            * 2nd invocation: signals that this given source file is indeed our source file

        Args:
            file_match (FileMatch): context representing a source file
        """
        # already locked to a file
        if self.file is not None:
            return
        # 1st invocation
        if file_match not in self.files:
            self.files.add(file_match)
        # 2nd invocation
        else:
            # double inclusion means total ownership
            self.file = file_match
            for iter_file in self.files.difference(set([file_match])):
                iter_file.remove(self)
            self.files = set([file_match])
            # propagate this new information internally
            self.selfCheck()

    def expel(self, file_match):
        """Expel us from the given file, it is no longer an option for us.

        Args:
            file_match (FileMatch): context representing a source file
        """
        if file_match in self.files:
            self.files.remove(file_match)
            # propagate this new information internally
            self.selfCheck()

    def isFileSuitable(self, src_ctx):
        """Check if the given source context can be a possible match, judging only by the files of both contexts.

        Args:
            src_ctx (context): source context of the candidate source function

        Return Value:
            True iff the src ctx is file-suitable as a match candidate
        """
        return src_ctx.file in self.files or self.isLinkerOptimizationCandidate(src_ctx)

    def isLinkerOptimizationCandidate(self, src_ctx):
        """Check if the given source context can be a possible match for a linker optimized version of our binary function.

        Args:
            src_ctx (context): source context of the candidate source function

        Return Value:
            True iff the src ctx is file-suitable as a collision match candidate
        """
        raise NotImplementedError("Subclasses should implement this!")

    def merged(self):
        """Check if this is a merged (collision) function.

        Return value:
            True iff this is a merged function
        """
        raise NotImplementedError("Subclasses should implement this!")
