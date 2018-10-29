from score_config import *
from elementals   import Logger
import libc_config as    libc
import logging
import json
import collections
import os

#################################
## Basic Global Configurations ##
#################################

IDA_PATH = '/opt/ida-7.1/ida'
SCRIPT_PATH = os.path.abspath('analyze_src_file.py')

##########################
## Basic Configurations ##
##########################

LIBRARY_NAME        = "Karta" 
LIBRARY_NAME_PREFIX = LIBRARY_NAME + "_" 
CONFIG_DIR_PATH     = "configs"
STATE_FILE_SUFFIX   = "_file_state.json"
LIBRARY_FILE_SUFFIX = "_library_state.json"

######################
## Global Variables ##
######################

src_seen_consts         = []
src_seen_strings        = []
src_functions_list      = []
src_functions_ctx       = []
src_file_mappings       = collections.OrderedDict()

src_instr_count         = 0
bin_instr_count         = 0
num_instr_samples       = 0

class CodeContext(object):
    """Abstract class that represents a code chunk's canonical representation

    Attributes:
        _name (str): name of the code chunk (function/location)
        _ea (int): effective address for the start of the code chunk
    """
    def __init__(self, name, ea):
        """Basic Ctor for the base class

        Args:
            name (str): name of the code chunk (function/location)
            ea (int): effective address for the start of the code chunk (or None if unknown yet)
        """
        self._name = name
        self._ea   = ea

    def matched(self):
        """Check if the code context was matched with src/bin counterpart

        Return Value:
            True iff the context was matched
        """
        raise NotImplementedError("Subclasses should implement this!")

    def match(self):
        """Returns the instance's match if already found it

        Return Value:
            A valid match if found one, None otherwise
        """
        raise NotImplementedError("Subclasses should implement this!")

    def declareMatch(self, match):
        """Declares a match between a source and a bin context

        Args:
            match (varies): the match context/ea
        """
        raise NotImplementedError("Subclasses should implement this!")

    def valid(self) :
        """Checks if the function is still valid (still active)

        Return Value:
            True iff the function still exists in the file matching process
        """
        raise NotImplementedError("Subclasses should implement this!")

    def active(self) :
        """Checks if the given function is still in the matching game

        Return Value:
            True iff the function is valid and wasn't matched yet
        """
        return self.valid() and not self.matched()

class ExternalFunction(CodeContext) :
    """This class describes a source-code point of view of an external function, using references from/to it

    Attributes:
        _hints (set): set of possible match (bin) candidates represented as eas
        _xrefs (set): set of xrefs to this external function, as seen in the source project
    """
    def __init__(self, name) :
        """Basic Ctor for the class using only the name (ea is unknown untill we will have a match)

        Args:
            name (str): name of the external function
        """
        super(ExternalFunction, self).__init__(name, None)
        self._hints = None
        self._xrefs = set()

    # Overriden base function
    def matched(self) :
        return self._ea is not None

    # Overriden base function
    def match(self) :
        return self._ea

    # Overriden base function
    def declareMatch(self, match):
        self._ea = match

    # Overriden base function
    def valid(self):
        return True

    def addXref(self, xref) :
        """Adds an xref to the function

        Args:
            xref (CodeContext): code context that calls (xrefs) our function
        """
        self._xrefs.add(xref)

    def removeXref(self, xref) :
        """Removes an xref from the function (the caller was probably found irrelevant for our search)

        Assumptions:
            xref is contained in our xrefs data structure

        Args:
            xref (CodeContext): code context that calls (xrefs) our function
        """
        self._xrefs.remove(xref)

    def used(self) :
        """Checks if our external function is still used by active functions

        Return Value:
            True iff the function is used (has at least 1 active xref)
        """
        return len(self._xrefs) > 0

    def addHints(self, hints) :
        """Adds a collection of (bin) hints for our match

        Args:
            hints (collection): a collection of (bin) match hints, represented as eas
        """
        if self._hints is None :
            self._hints = set(hints)
        else :
            self._hints = self._hints.intersection(hints)
        # check for a match
        if len(self._hints) == 1:
            self.declareMatch(list(self._hints)[0])

class ComparableContext(CodeContext) :
    """Base class representing the canonical representation of CodeContexts with the ability of being compared one to another

    Attributes:
        _consts (set): set of numeric constants
        _const_ranks (dict): mapping from numeric const to it's score (calculated only once on start)
        _strings (set): set of string
        _calls (set): set of (library) function calls (containing ComparableContext instances)
        _externals (set): set of external function calls
    """
    def __init__(self, name, ea) :
        super(ComparableContext, self).__init__(name, ea)
        # artefacts
        self._consts      = set()
        self._const_ranks = {}
        self._strings     = set()
        # call references
        self._calls       = set()
        self._externals   = set()
        # source/bin match
        self._match       = None

    # Overriden base function
    def matched(self) :
        return self._match is not None

    # Overriden base function
    def match(self) :
        return self._match

    # Overriden base function
    def declareMatch(self, match):
        self._match = match

    def isPartial(self) :
        """Tells if the current instance is a full function, or only a partial one (an island)

        Return Value:
            True iff a partial function
        """
        raise NotImplementedError("Subclasses should implement this!")

    def recordConst(self, const) :
        """Records a numeric constant artefact in the code's artefacts list

        Args:
            const (int): numric constant artefact
        """
        self._consts.add(const)

    def recordString(self, string) :
        """Records a string artefact in the code's artefacts list

        Args:
            string (str): string artefact
        """
        self._strings.add(string)

    def recordCall(self, call) :
        """Records a function call artefact in the code's artefacts list

        Args:
            call (varies): name of ea that identifies the (basic) function call
        """
        self._calls.add(call)

    def rankConsts(self) :
        """Ranks all of the consts of our context - should be done only once on init"""
        for num_const in self._consts :
            self._const_ranks[num_const] = rankConst(num_const, self)

    @staticmethod
    def compareConsts(src_ctx, bin_ctx):
        """Compares the numerical constants of both contexts and returns the matching score

        Args:
            src_ctx (ComparableContext): context representing the source function
            bin_ctx (ComparableContext): context representing the binary function

        Return value
            floating point score for the constants comparison
        """
        score = 0
        # earn points by ranking the consts in the intersection
        for const in src_ctx._consts.intersection(bin_ctx._consts) :
            score += src_ctx._const_ranks[const]
        # deduce points by ranking the consts in the symmetric difference
        for const in src_ctx._consts.difference(bin_ctx._consts) :
            score -= src_ctx._const_ranks[const]
        for const in bin_ctx._consts.difference(src_ctx._consts) :
            score -= bin_ctx._const_ranks[const]
        # give a boost for a perfect match
        if len(src_ctx._consts) > 0 and src_ctx._consts == bin_ctx._consts :
            score += ARTEFACT_MATCH_SCORE
        return score

    @staticmethod
    def compareString(src_ctx, bin_ctx):
        """Compares the strings of both contexts and returns the matching score

        Args:
            src_ctx (ComparableContext): context representing the source function
            bin_ctx (ComparableContext): context representing the binary function

        Return value
            floating point score for the strings comparison
        """
        score = 0
        # start with a bonus score in case the string is contained in the source function's name
        score += STRING_NAME_SCORE * len(filter(lambda s : s in src_ctx._name, bin_ctx._strings))
        # now actually match the strings (intersection and symmetric difference)
        for string in src_ctx._strings.intersection(bin_ctx._strings) :
            score += len(string) * STRING_MATCH_SCORE
            # duplicate the bonus in this case
            if string in src_ctx._name :
                score += STRING_NAME_SCORE
        # deduce points for strings in the symmetric difference
        for string in src_ctx._strings.symmetric_difference(bin_ctx._strings) :
            score -= len(string) * STRING_MISMATCH_SCORE
        # give a boost for a perfect match
        if len(src_ctx._strings) > 0 and src_ctx._strings == bin_ctx._strings :
            score += ARTEFACT_MATCH_SCORE
        return score

    @staticmethod
    def compareCalls(src_ctx, bin_ctx):
        """Compares the function calls of both contexts and returns the matching score

        Args:
            src_ctx (ComparableContext): context representing the source function
            bin_ctx (ComparableContext): context representing the binary function

        Return value
            floating point score for the calls comparison
        """
        score = -1 * abs(len(src_ctx._calls) - len(bin_ctx._calls)) * CALL_COUNT_SCORE
        # penalty for missing matched calls
        src_matched = filter(lambda x : x.matched(), src_ctx._calls)
        bin_matched = filter(lambda x : x.matched(), bin_ctx._calls)
        mismatching  = []
        mismatching += filter(lambda x : x._match not in bin_ctx._calls, src_matched)
        mismatching += filter(lambda x : x._match not in src_ctx._calls, bin_matched)
        matching = filter(lambda x : x._match in bin_ctx._calls, src_matched) 
        # the penalty is halved because we the list will most probably contain duplicates
        score -= CALL_COUNT_SCORE * len(mismatching) * 1.0 / 2
        score += MATCHED_CALL_SCORE * len(matching)
        # give a boost for a perfect match
        if len(mismatching) == 0 and len(src_ctx._calls) > 0 and len(src_ctx._calls) == len(bin_ctx._calls) :
            score += ARTEFACT_MATCH_SCORE
        return score

    @staticmethod
    def compareExternals(src_ctx, bin_ctx):
        """Compares the (matched) external function calls of both contexts and returns the matching score

        Args:
            src_ctx (ComparableContext): context representing the source function
            bin_ctx (ComparableContext): context representing the binary function

        Return value
            floating point score for the external calls comparison
        """
        # penalty for number of missing external calls
        score = -1 * abs(len(src_ctx._externals) - len(bin_ctx._externals)) * EXTERNAL_COUNT_SCORE
        for external in filter(lambda x : x.matched(), src_ctx._externals) :
            # check for a hit
            if external._ea in bin_ctx._externals :
                if external._name in libc.libc_function_names :
                    score += LIBC_COMP_FUNC_MATCH_SCORE if external._name in libc.libc_comp_function_names else LIBC_FUNC_MATCH_SCORE
                else :
                    score += EXT_FUNC_MATCH_SCORE
        # give a boost for a perfect match
        if len(src_ctx._externals) > 0 and len(src_ctx._externals) == len(bin_ctx._externals) :
            score += ARTEFACT_MATCH_SCORE
        return score

class IslandContext(ComparableContext) :
    """This class describes the canonical representation of a (bin) "Island" function that lives inside another binary function

    Attributes:
        _xrefs (set): set of (library) function xrefs (containing ComparableContext instances)
        _match (FunctionContext): the matched source function instance, or None if wasn't matched yet
    """
    def __init__(self, name, ea) :
        super(IslandContext, self).__init__(name, ea)
        self._xrefs = set()

    # Overriden base function
    def isPartial(self) :
        return True

    # Overriden base function
    def valid(self) :
        return True

    def compare(self, src_ctx, logger) :
        """Compares our island to a potential source match

        Args:
            src_ctx (FunctionContext): src context representing a source function (potential match)
            logger (logger): logger instance

        Return Value:
            floating point score for the entire match
        """
        score = 0
        logger.addIndent()
        boost_score = len(src_ctx._blocks) <= MINIMAL_BLOCKS_BOOST
        # 1. Match constants
        const_score = ComparableContext.compareConsts(src_ctx, self)
        logger.debug("Const score: %f", const_score)
        score += const_score
        # 2. Match strings
        string_score = ComparableContext.compareString(src_ctx, self)
        logger.debug("String score: %f", string_score)
        score += string_score
        # 3. Match calls
        calls_score = ComparableContext.compareCalls(src_ctx, self)
        logger.debug("Calls score: %f", calls_score)
        score += calls_score
        # 4. Match external calls
        externals_score = ComparableContext.compareExternals(src_ctx, self)
        logger.debug("Externals score: %f", externals_score)
        score += externals_score
        # 5. Boost the score
        if boost_score :
            score *= 2
            logger.debug("Score boost")
        # Overall result
        logger.debug("Overall score is: %f", score)
        logger.removeIndent()
        return score

class FunctionContext(ComparableContext):
    """This class describes the canonical representation of a (bin) "Island" function that lives inside another binary function

    Attributes:
        _unknowns (set): temporary set of (source) function names frfom outside of our compilation file
        _xrefs (set): set of (library) function xrefs (containing ComparableContext instances)
        _frame (int): size (in bytes) of the function's stack frame
        _instrs (int): number of code instruction in our function
        _blocks (list): (sorted) list containing the number of instructions in each code block
        _call_order (dict): a mapping of: call invocation => set of call invocations that can reach it
        _src_index (int): (source only) unique id representing the index of the function in the function list
        _bin_index (int): (binary only) unique id representing the index of the function in the function list        
        _call_hints (set): (binary only) set of potential matches derived by lists of function calls from matched functions
        _xref_hints (list): (binary only) list potential matches derived by lists of xrefs from matched functions
        _followers (set): (source only) set of binary functions that use us as a potential match hint
        _file (FileMatch): (source only) actual File Match instance representing our source file
        _exists (bool): (source only) validity flag marking our existance in the source (according to info from the binary match)
        _file_hint (str): (source_only) source file name string if exists inside function, None otherwise
        _is_static (bool): (source mode) True iff the function is not exported outside of it's local *.O file
                           (bin mode) False iff the function is (code) referenced from outside the library
    """

    def __init__(self, name, ea) :
        super(FunctionContext, self).__init__(name, ea)
        # temporary field
        self._unknowns   = set()
        # artefacts
        self._xrefs      = set()
        self._frame      = None
        self._instrs     = None
        self._blocks     = []
        self._call_order = None
        # source/binary indices (unique ids)
        self._src_index  = None
        self._bin_index  = None
        # matching hints
        self._call_hints = None
        self._xref_hints = []
        self._followers  = set()
        self._files      = set()
        self._file       = None
        # validity flag
        self._exists     = True
        # File (source) hint
        self._file_hint  = None
        # Compilation clues
        self._is_static  = False

    # Overriden base function
    def declareMatch(self, match):
        self._match = match
        # notify our followers that we are now out of the game
        for follower in self._followers :
            follower.removeHint(self, clear = False)
        # notify our hints that we are out of the game
        if self._call_hints is not None :
            for hint in list(self._call_hints) :
                self.removeHint(hint, clear = True)
        for hint in list(self._xref_hints) :
            self.removeHint(hint, clear = True)
        self._followers = set()

    # Overriden base function
    def isPartial(self) :
        return False

    # Overriden base function
    def valid(self):
        return self._exists

    def recordUnknown(self, unknown) :
        """Records a function call to an unknown function (only happens in source contexts)

        Args:
            unknown (str): name of an unknown source function
        """
        self._unknowns.add(unknown)

    def setFrame(self, frame) :
        """Sets the size of the stack frame for our function

        Args:
            frame (int): frame size (in bytes) of our function
        """
        self._frame = frame

    def setInstrCount(self, num_instrs) :
        """Sets the number of code instructionsin our function

        Args:
            num_instrs (int): number of instructions in the function
        """
        self._instrs = num_instrs

    def recordBlock(self, block) :
        """Records a code block in our function's code flow

        Args:
            block (int): number of instructions in the given code block
        """
        self._blocks.append(block)

    def setCallOrder(self, mapping) :
        """Sets the call order mapping: call invocation => set of call invocations that can reach it

        Args:
            mapping (dict): mapping of the call order
        """
        self._call_order = mapping

    def markStatic(self) :
        """Marks our source function as a non-exported (static) function"""
        self._is_static = True

    def static(self):
        """Checks if this is a static function

        Return value:
            True iff this is a static function
        """
        return self._is_static

    def disable(self) :
        """Marks our source function as non-existant (probably ifdeffed out)"""
        self._exists = False
        # keep on recursively with our external functions
        for ext in self._externals :
            ext.removeXref(self)

    def used(self) :
        """Check if our function is used, i.e. has ingoing/outgoing reference to other functions

        Return value:
            True iff the function has any call/xref to other functions
        """
        return len(self._calls) + len(self._xrefs) > 0

    def isHinted(self) :
        """(binary only) Check if our function was hinted at sometimes - meaning we should suspect it is a valid function

        Return value:
            True iff the function has any call/xref hint granted by other functions
        """
        return (self._call_hints is not None and len(self._call_hints) > 0) or len(self._xref_hints) > 0

    def addFollower(self, bin_ctx) :
        """Adds a binary follower to our source context. He thinks we are a potential (hint) match

        Args:
            bin_ctx (ComparableContext): binary function that follows us using a hint
        """
        self._followers.add(bin_ctx)         

    def addHints(self, hints, is_call) :
        """Adds a set of (source) match hints to help us filter our existing hints

        Args:
            hint (collection): a collection of (source) function potential matches (containing FunctionContext instances)
            is_call (bool): True iff call hints, otherwise xref hints
        """
        new_hints = filter(lambda x : x.isValidCandidate(self), hints)
        if is_call :
            if self._call_hints is None :
                self._call_hints = set(new_hints)
                for hint in new_hints :
                    hint.addFollower(self)
            else :
                for dropped in self._call_hints.difference(new_hints) :
                    dropped.removeFollower(self)
                self._call_hints = self._call_hints.intersection(new_hints)
        else :
            self._xref_hints += new_hints
            for hint in new_hints :
                hint.addFollower(self)

    def linkFile(self, file_match) :
        """Link our (binary) context to a code file (FileMatch instance)

        Notes:
            * 1st invocation: adds the given source file as a potential candidate
            * 2nd invocation: signals that ths given source file is indeed our source file

        Args:
            file_match (FileMatch): context representing a source file
        """
        # already locked to a file
        if self._file is not None :
            return
        # 1st invocation
        if file_match not in self._files :
            self._files.add(file_match)
        # 2nd invocation
        else :
            # double inclusion means total ownership
            self._file = file_match
            for iter_file in self._files.difference(set([file_match])) :
                # in both cases my index will be lower / bigger than his range (meaning external remove)
                iter_file.remove(file_match._src_index_start, self)
            self._files = set([file_match])
            # good time to double check our hints
            self.checkHints()

    def expel(self, file_match) :
        """Expels us from the given source file, it is no longer an option for us

        Args:
            file_match (FileMatch): context representing a source file
        """
        if file_match in self._files :
            self._files.remove(file_match)
            # check again our hints (if won't do it again later)
            if self._file is None :
                self.checkHints()

    def removeFollower(self, bin_ctx) :
        """Removes a (binary) follower from our watch list (he was probably matched without us)

        Args:
            bin_ctx (ComparableContext): a follower (binary) function
        """
        if bin_ctx in self._followers :
            self._followers.remove(bin_ctx)

    def removeHint(self, src_ctx, clear = True) :
        """Removes a (source) hint from our possible candidates (he was probably matched without us)

        Args:
            src_ctx (FunctionContext): a hint (source) function
            clear (bool, optional): True iff should also remove us from following him (True by default)
        """
        if clear :
            src_ctx.removeFollower(self)
        if self._call_hints is not None :
            while src_ctx in self._call_hints :
                self._call_hints.remove(src_ctx)
        while src_ctx in self._xref_hints :
            self._xref_hints.remove(src_ctx)

    def checkHints(self) :
        """Double checks our hints, and keeps only those who match our possible file candidates"""
        for hint in set(self._xref_hints).union(self._call_hints if self._call_hints is not None else set()) :
            # bye bye, hint
            if not hint.isValidCandidate(self) :
                self.removeHint(hint)

    def hasFileHint(self) :
        """Checks if the functions contains a file hint string
            
        Return Value:
            True iff contains a source file name string hint
        """
        return self._file_hint is not None

    def fileHint(self) :
        """Returns the file' hint string

        Assumption:
            hasFileHint() == True
            
        Return Value:
            source file name string hint
        """
        return self._file_hint

    def checkFileHint(self) :
        """After all strings were recorded, checks if has a file string hint
        
        Return Value :
            source file name string hint iff found one, None otherwise
        """
        for string in self._strings :
            name_parts = string.split('.')
            if len(name_parts) != 2 :
                continue
            file_name = self._file.split(os.path.sep)[-1].split('.')[0]
            if name_parts[0] == file_name and name_parts[1].lower() in ['c', 'cpp', 'c++'] :
                self._file_hint = string
                return self._file_hint
        return None

    def isValidCandidate(self, bin_ctx) :
        """(source only) Check if the given binary context is a valid match candidate

        Args:
            bin_ctx (ComparableContext): context representing a binary function (potential match)
        
        Return Value:
            False iff the binary context was found as an invalid match candidate
        """
        # 0. Both must be in the game
        if not self.active() or not bin_ctx.active() :
            return False

        # 1. They must be in the same file
        if self._file not in bin_ctx._files :
            return False

        # 2. A static function can not have an xref from outside the library (weak because of possible inlining)
        if self.static() and not bin_ctx.static() :
            return False

        # If reached this line, the candidate is probably fine
        return True

    def compare(self, bin_ctx, logger) :
        """Compares our (source) function to a potential binary match

        Args:
            bin_ctx (ComparableContext): context representing a binary function (potential match)
            logger (logger): logger instance

        Return Value:
            floating point score for the entire match
        """
        score = 0
        logger.addIndent()
        # 0. prepare the instruction ratio (if has one already)
        instr_ratio = (src_instr_count * 1.0 / bin_instr_count) if num_instr_samples >= INSTR_RATIO_COUNT_THRESHOLD else 1
        boost_score = len(self._blocks) <= MINIMAL_BLOCKS_BOOST and len(bin_ctx._blocks) <= MINIMAL_BLOCKS_BOOST
        boost_score = boost_score and self._call_hints is None and len(self._xref_hints) == 0 and bin_ctx._call_hints is None and len(bin_ctx._xref_hints) == 0
        # 1. Match constants
        const_score = ComparableContext.compareConsts(self, bin_ctx)
        logger.debug("Const score: %f", const_score)
        score += const_score
        # 2. Match strings
        string_score = ComparableContext.compareString(self, bin_ctx)
        logger.debug("String score: %f", string_score)
        score += string_score
        # 3. Match sizes
        function_size_score = -1 * abs(self._instrs - bin_ctx._instrs * instr_ratio) * INSTR_COUNT_SCORE
        # check for a probable match
        if abs(function_size_score) <= INSTR_COUNT_THRESHOLD * INSTR_COUNT_SCORE :
            function_size_score += ARTEFACT_MATCH_SCORE
        logger.debug("Function size score: %f", function_size_score)
        score += function_size_score
        # 4. Match stack frames
        frame_size_score = -1 * abs(self._frame - bin_ctx._frame) * FUNC_FRAME_SCORE
        # check for a probable match
        if abs(frame_size_score) <= FRAME_SIZE_THRESHOLD * FUNC_FRAME_SCORE :
            frame_size_score += ARTEFACT_MATCH_SCORE
        logger.debug("Frame size score: %f", frame_size_score)
        score += frame_size_score
        # 5. Match calls
        calls_score = ComparableContext.compareCalls(self, bin_ctx)
        logger.debug("Calls score: %f", calls_score)
        score += calls_score
        # 6. Match code blocks
        code_blocks_score = 0
        for index, block in enumerate(self._blocks) :
            code_blocks_score -= abs(self._blocks[index] - ((bin_ctx._blocks[index] * instr_ratio) if index < len(bin_ctx._blocks) else 0)) * BLOCK_MATCH_SCORE
        for j in xrange(index + 1, len(bin_ctx._blocks)) :
            code_blocks_score -= bin_ctx._blocks[j] * BLOCK_MISMATCH_SCORE * instr_ratio
        # check for a probable match
        if abs(code_blocks_score) <= INSTR_COUNT_THRESHOLD * INSTR_COUNT_SCORE :
            code_blocks_score += ARTEFACT_MATCH_SCORE
        logger.debug("Code blocks score: %f", code_blocks_score)
        score += code_blocks_score
        # 7. Match function calls (hints)
        call_hints_score = 0
        if bin_ctx._call_hints is not None and len(bin_ctx._call_hints) > 0 and self in bin_ctx._call_hints :
            call_hints_score += FUNC_HINT_SCORE * 1.0 / len(bin_ctx._call_hints)
        logger.debug("Call hints score: %f", call_hints_score)
        score += call_hints_score
        # 8. Match xrefs calls (hints)
        if len(bin_ctx._xref_hints) > 0 :
            xref_hints_score = FUNC_HINT_SCORE * bin_ctx._xref_hints.count(self) * 1.0 / len(bin_ctx._xref_hints)
            logger.debug("Xref hints score: %f", xref_hints_score)
            score += xref_hints_score
        # 9. Existance check (followers) or non static binary function
        if len(self._followers) > 0 or not bin_ctx.static() :
            score += EXISTANCE_BOOST_SCORE
            logger.debug("We have (%d) followers / are static (%s) - grant an existance bonus: %f", len(self._followers), str(bin_ctx.static()), EXISTANCE_BOOST_SCORE)
        # 10. Match external calls
        externals_score = ComparableContext.compareExternals(self, bin_ctx)
        logger.debug("Externals score: %f", externals_score)
        score += externals_score
        # 11. Possible static deduction
        if self.static() :
            for xref in bin_ctx._xrefs :
                if self._file not in xref._files :
                    score -= STATIC_VIOLATION_PENALTY
        # 12. Score boost
        if boost_score :
            score *= 2
            logger.debug("Score boost")
        # Overall result
        logger.debug("Overall score is: %f", score)
        logger.removeIndent()
        return score

    def serialize(self) :
        """Serializes the context into a dict

        Return Value:
            dict representing the context instance, prepared for a future JSON dump
        """
        result = collections.OrderedDict()
        result['Function Name'] = self._name
        result['Function EA'] = self._ea
        result['Instruction Count'] = self._instrs
        result['Stack Frame Size'] = self._frame
        result['Is Static'] = self._is_static
        result['Numeric Consts'] = list(self._consts)
        result['Strings'] = list(self._strings)
        result['Calls'] = list(self._calls)
        result['Unknowns'] = list(self._unknowns)
        result['Code Block Sizes'] = self._blocks
        result['Call Order'] = self._call_order
        return result

    @staticmethod
    def deserialize(serialized_ctx) :
        """Deserializes the stored context from it's file representation dict

        Args:
            serialized_ctx (dict): a dict containg a serialize()d context instance

        Return value:
            The newly created context instance, built according to the serialized form
        """
        context = FunctionContext(serialized_ctx['Function Name'], serialized_ctx['Function EA'])
        # Numeric Consts
        map(lambda x : context.recordConst(x), serialized_ctx['Numeric Consts'])
        # Strings
        map(lambda x : context.recordString(x), serialized_ctx['Strings'])
        # Function Calls
        map(lambda x : context.recordCall(x), serialized_ctx['Calls'])
        # Unknowns
        map(lambda x : context.recordUnknown(x), serialized_ctx['Unknowns'])
        # Frame size
        context.setFrame(serialized_ctx['Stack Frame Size'])
        # Function size
        context.setInstrCount(serialized_ctx['Instruction Count'])
        # Function Blocks
        map(lambda x : context.recordBlock(x), serialized_ctx['Code Block Sizes'])
        # Call order
        context.setCallOrder(serialized_ctx['Call Order'])
        # Is static
        if serialized_ctx['Is Static'] :
            context.markStatic()
        # Now rank the consts
        context.rankConsts()
        return context
        
def functionsToFile(file_name, contexts) :
    """Stores all of the file's functions into a state file
    
    Args:
        file_name (str): file name of a compiled source file
        contexts (list): list of FunctionContext instances for all of the functions in the file
    """
    # Temporary JSON (later will be merged to a single JSON)
    fd = open(file_name + STATE_FILE_SUFFIX, "w")
    json.dump(map(lambda c : c.serialize(), contexts), fd)
    fd.close()

def constructConfigPath(library_name, library_version):
    """Generates the name for the JSON config file that will store the library's canonical data
    
    Args:
        library_name (str): name of the library (as extracted by the identifiers)
        library_version (str): version of the library (as extracted by the identifiers)

    Return value:
        file name for the JSON config file
    """
    return library_name + "_" + library_version + ".json"

def recordInstrRatio(src_instr, bin_instr) :
    """Records a single ratio sample for measuring src_instr / bin_instr ratio
    
    Args:
        src_instr (int): number of instructions in given source sample
        bin_instr (int): number of instructions in given binary sample
    """
    global src_instr_count, bin_instr_count, num_instr_samples

    src_instr_count   += src_instr
    bin_instr_count   += bin_instr
    num_instr_samples += 1

def countSetBits(const) :
    """Counts the set ('1') bits in the given numeric constant
    
    Args:
        const (int): numeric constant to rank

    Return Value:
        Number of set ('1') bits
    """
    # we only work on unsigned values
    if const < 0 :
        const += 2 ** NUM_BITS_IN_CONST
    # simply count them
    return bin(const).count('1')

def measureBitsVariance(const) :
    """Measures the bits "entropy", i.e. the variance of the bit flips
    
    Args:
        const (int): numeric constant to rank

    Return Value:
        Variance level of the bit flips
    """
    variance = 0
    level = 1
    const = bin(const)[2:]
    while const.count('0') != len(const) and level < 4:
        cur_const = '1' if const[0] != const[-1] else '0'
        last_bit = const[0]
        for bit in const[1:] :
            cur_const += '1' if bit != last_bit else '0'
            last_bit = bit
        const = cur_const
        variance += level * abs(NUM_BITS_IN_CONST * 0.5 - abs(cur_const.count('1') - NUM_BITS_IN_CONST * 0.5))
        level += 1
    return variance

def measureBitsEntropy(const) :
    """Uses heuristics to measure the "entropy" of the given numeric value
    
    Args:
        const (int): numeric constant to be measured

    Return Value:
        Overall "entropy" score of the given numeric constant
    """
    # we only work on unsigned values
    if const < 0 :
        const += 2 ** NUM_BITS_IN_CONST
    # variance score (embeds inside it the number of bits)
    return measureBitsVariance(const) * 1.0 / (NUM_BITS_IN_CONST / 2)

def rankConst(const, context) :
    """Scores a given constant, in the context of its function
    
    Args:
        const (int): numeric constant to rank
        context (FunctionContext): function context or None (for islands)

    Return Value:
        Overall score of the given numeric constant
    """
    # 0. Ignore stack variable offsets
    if context is not None and const < context._frame + FRAME_SAFETY_GAP :
        return 0    
    # 1. Measure the entropy
    score = measureBitsEntropy(const)
    # 2. Scale it: use a wider range, and spread the values
    score = score * score
    # 3. Boost special values
    if const in CONST_SPECIAL_VALUES :
        score += CONST_BOOST_SPECIAL
    # 4. Boost bit flags that are bigger than the frame size
    if context is not None and countSetBits(const) == 1 and const > context._frame :
        score += CONST_BOOST_BIT_FLAG
    return score

def resetRatio():
    """Prepares the ratio variables for a new script execution"""
    global src_instr_count, bin_instr_count, num_instr_samples
    # same as the init list on the top of the file
    src_instr_count         = 0
    bin_instr_count         = 0
    num_instr_samples       = 0

def initUtils():
    """Prepares the utils global variables for a new script execution"""
    global src_seen_consts, src_seen_strings, src_functions_list, src_functions_ctx, src_file_mappings
    # same as the init list on the top of the file
    src_seen_consts         = []
    src_seen_strings        = []
    src_functions_list      = []
    src_functions_ctx       = []
    src_file_mappings       = collections.OrderedDict()
    # don't forget the instruction ratio
    resetRatio()

def getSourceFunctions() :
    """Returns the data-structures of the analyzed source functions
    
    Return Value:
        src_functions_list, src_functions_ctx, src_file_mappings
    """
    return src_functions_list, src_functions_ctx, src_file_mappings

def setIDAPath():
    """Updates the IDA path according to input from the user"""
    global IDA_PATH

    new_path = raw_input("[+] Please insert the command (path) need in order to execute IDA (%s): " % (IDA_PATH))
    if len(new_path.strip()) != 0 :
        IDA_PATH = new_path

def getIDAPath():
    """Returns the updated IDA path

    Return Value:
        The (updated) path to the IDA program
    """
    return IDA_PATH

def parseFileStats(file_name, functions_config) :
    """Parses the file metadata from the given file
    
    Args:
        file_name (str): name of the compiled *.o function
        functions_config (list): list of serialized functions, as extracted from the JSON file
    """
    global src_seen_consts, src_seen_strings, src_functions_list, src_functions_ctx, src_file_mappings

    src_file_mappings[file_name] = []
    for func_config in functions_config :
        context = FunctionContext.deserialize(func_config)
        context._file = file_name
        # accumulate the artefacts
        src_seen_consts  += context._consts
        src_seen_strings += context._strings
        # register the seen function
        src_functions_list.append(context._name)
        src_functions_ctx.append(context)
        src_file_mappings[file_name].append(context)

def isAnchor(context, logger) :
    """Checks if the given context represents an Anchor function
    
    Args:
        context (FunctionContext): canonical representation of a source function
        logger (logger): logger instance

    Return Value:
        is string criteria (True / False), threshold count, Matching anchor criteria (list of string for instance), or None if not an anchor
    """

    case = 1
    max_case = 5
    while case <= max_case :
        # 1. Huge unique string
        if case == 1 :
            huge_strings = filter(lambda x : src_seen_strings.count(x) == 1, filter(lambda x : len(x) >= STRING_HUGE_LIMIT, context._strings))
            if len(huge_strings) >= STRING_HUGE_GROUP :
                logger.debug("Found an Anchor: %s ==> Unique HUGE string (%d)", context._name, len(huge_strings[0]))
                return True, STRING_HUGE_GROUP, huge_strings
        # 2. Unique string with a function name in it
        elif case == 2 :
            for unique_str in filter(lambda x : src_seen_strings.count(x) == 1, context._strings) :
                for func_name in src_functions_list :
                    if func_name in unique_str :
                        logger.debug("Found an Anchor: %s ==> Unique string (%s) containing a function name (%s)", context._name, unique_str, func_name)
                        return True, 1, [unique_str]
        # 3. X unique strings with long length
        elif case == 3 :
            unique_long_strings = filter(lambda x : src_seen_strings.count(x) == 1, filter(lambda x : len(x) >= STRING_LONG_LIMIT, context._strings))
            if len(unique_long_strings) >= STRING_LONG_GROUP :
                logger.debug("Found an Anchor: %s ==> %d unique long strings", context._name, len(unique_long_strings))
                return True, STRING_LONG_GROUP, unique_long_strings
        # 4. X unique strings with medium length
        elif case == 4 :
            unique_medium_strings = filter(lambda x : src_seen_strings.count(x) == 1, filter(lambda x : len(x) >= STRING_MEDIUM_LIMIT, context._strings))
            if len(unique_medium_strings) >= STRING_MEDIUM_GROUP :
                logger.debug("Found an Anchor: %s ==> %d unique medium strings", context._name, len(unique_medium_strings))
                return True, STRING_MEDIUM_GROUP, unique_medium_strings
        # 5. Unique const with high entropy
        elif case == 5 :
            unique_complex_consts = filter(lambda x : src_seen_consts.count(x) == 1, filter(lambda x : rankConst(x, context) >= CONST_COMPLEX_LIMIT, context._consts))
            if len(unique_complex_consts) >= CONST_COMPLEX_GROUP :
                logger.debug("Found an Anchor: %s ==> %d unique complex consts: %s", context._name, len(unique_complex_consts), hex(unique_complex_consts[0]))
                return False, CONST_COMPLEX_GROUP, unique_complex_consts
        case += 1
    # we found nothing if we reached this line
    return False, 0, None

def isAgent(context, unique_strings, unique_consts, logger) :
    """Checks if the given context represents an Agent function inside it's file
    
    Args:
        context (FunctionContext): canonical representation of a source function
        unique_strings (set): set of unique strings to be used for the scoring
        unique_consts (set): set of unique (numeric) consts to be used for the scoring
        logger (logger): logger instance

    Return Value:
        is string criteria (True / False), threshold count, Matching agent criteria (list of string for instance), or None if not an agent
    """

    case = 1
    max_case = 3
    while case <= max_case :
        # 1. Medium unique string
        if case == 1 :
            medium_strings = filter(lambda x : x in unique_strings, filter(lambda x : len(x) >= STRING_MEDIUM_LIMIT, context._strings))
            if len(medium_strings) > 0 :
                logger.debug("Found an Agent: %s ==> Unique medium string (%d)", context._name, len(medium_strings[0]))
                return True, 1, medium_strings
        # 2. X unique strings with short length
        elif case == 2 :
            unique_short_strings = filter(lambda x : x in unique_strings, filter(lambda x : len(x) >= STRING_SHORT_LIMIT, context._strings))
            if len(unique_short_strings) >= STRING_SHORT_GROUP :
                logger.debug("Found an Agent: %s ==> %d unique long strings", context._name, len(unique_short_strings))
                return True, STRING_SHORT_GROUP, unique_short_strings
        # 3. Unique const with medium entropy
        elif case == 3 :
            unique_medium_consts = filter(lambda x : x in unique_consts, filter(lambda x : rankConst(x, context) >= CONST_MEDIUM_LIMIT, context._consts))
            if len(unique_medium_consts) > 0 :
                logger.debug("Found an Agent: %s ==> %d unique medium consts", context._name, len(unique_medium_consts))
                return False, 1, unique_medium_consts
        case += 1
    # we found nothing if we reached this line
    return False, 0, None
