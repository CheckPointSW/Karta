from ida_utils  import *

import os
import sys
import time

####################
## Global Configs ##
####################

REASON_ANCHOR           = "Anchor - Complex unique string / const"
REASON_FILE_HINT        = "Hint - Includes filename string"
REASON_AGENT            = "Agent - File-unique string / const"
REASON_NEIGHBOUR        = "Neighbour matching"
REASON_SINGLE_CALL      = "Single called (xref) option"
REASON_SINGLE_XREF      = "Single caller (xref) option"
REASON_FILE_SINGLETON   = "Last (referenced) function in file"
REASON_CALL_ORDER       = "Call order in caller function"
REASON_SWALLOW          = "Swallow - Identified IDA analysis problem"
REASON_SCORE            = "Score-based Matching"

######################
## Global Variables ##
######################

src_file_names          = []        # Orderred list of source file names
src_anchor_list         = []        # List of (src) indices of the anchor functions
bin_anchor_list         = []        # List of (bin) indices of the (matched) anchor functions
matched_anchors_ea      = {}        # Mapping of anchor functions: source index => matched ea
src_external_functions  = {}        # Mapping of external functions: name => external context
bin_external_functions  = set()     # Set of eas for all external functions

src_functions_list      = []        # Stored near us, to avoid problems with included version from utils.py
src_functions_ctx       = []        # Stored near us, to avoid problems with included version from utils.py
src_file_mappings       = {}        # Stored near us, to avoid problems with included version from utils.py
bin_functions_ctx       = {}        # bin ea => bin function ctx
match_files             = []        # Orderred list of FileMatch instances, each for every source file

match_round_candidates  = []        # valid match candidates (containing match records)
match_round_src_index   = {}        # src index => match record
match_round_bin_ea      = {}        # bin ea => match record
match_round_losers      = []        # losers (to be tracked for changes) list for the match round (containing match records)

src_unused_functions    = set()     # Set of (src) indices for unusd functions (disabled functions)
ext_unused_functions    = set()     # Set of (src) names for unused external functions (all callers were disabled)

function_matches        = {}        # Dictionary of all (non-external) matches: src index => bin ea
bin_matched_ea          = {}        # Reverse dictionary for all matches: bin ea => src index / external ctx
matching_reason         = {}        # Dictionary of all (non-external) matching reasons: src index => reason

changed_functions       = {}        # Mappings for hints derived at the current matching round: src index => set of bin function ea
once_seen_couples_src   = {}        # archive of all seen matching attempts. Mapping from src index => bin ctx
once_seen_couples_bin   = {}        # archive of all seen matching attempts. Mapping from bin ea => src index
call_hints_records      = []        # List of records describing the hints metadata, used as supplementary 

anchor_hints            = []        # Temporary global holding the hints derived from the anchor matching
str_file_hints          = set()     # global list of strings that hints about their source code file name

floating_bin_functions  = None      # single global dictionary for the binary function contexts in the floating files
floating_files          = []        # list of currently floating files

bin_suggested_names     = {}        # Suggested Names for the matched and unmatched binary functions: ea => name

logger                  = None      # Global logger instance
library_name            = None      # name of the matched open source library
        

class MatchSequence(object) :
    """A class representing a (geographic) sequence of matched binary functions

    Attributes:
        _bin_lower_ctx (FunctionContext): the lowest matched binary function in the sequence
        _bin_upper_ctx (FunctionContext): the uppmost matched binary function in the sequence

    Notes:
        We can NOT save indices (bin_index), since the file's bin functions list is dynamic.
        Therefor, we save full contexts, and search their index in the list each time we need it.
    """
    def __init__(self, bin_ctx) :
        """Creates a match sequence that contains a single (matched) binary function

        Args:
            bin_ctx (FunctionContext): the first context in our match sequence
        """
        self._bin_lower_ctx = bin_ctx
        self._bin_upper_ctx = bin_ctx

    def enlarge(self, bin_ctx, is_lower) :
        """Add a new matched binary context to the top/bottom of the current sequence

        Args:
            bin_ctx (FunctionContext): newly added binary context
            is_lower (bool): True iff should be inserted at the lower end
        """
        if is_lower :
            self._bin_lower_ctx = bin_ctx
        else :
            self._bin_upper_ctx = bin_ctx

    def merge(self, sequence, is_lower) :
        """Merge a sequence into our own sequence (thus killing the supplied sequence)

        Args:
            sequence (MatchSequence): merged match sequence instance
            is_lower (bool): True iff should be inserted at the lower end
        """
        if is_lower :
            self._bin_lower_ctx = sequence._bin_lower_ctx
        else :
            self._bin_upper_ctx = sequence._bin_upper_ctx

class FileMatch(object) :
    """A class representing a match attempt of a full source file

    Attributes:
        _name (str): name of the file (from the list of compiled files)
        _located (bool): True iff already located atleast one function in the file (otherwise we till don't know where it is)
        _valid (bool): True iff the file play a role in the matching process (False means it was probably ifdeffed out)
        _src_index_start (int): source index of the first function in the source file
        _src_index_end (int): source index of last function in the source file
        _bin_functions_ctx (list): list of all candidate binary functions for this file (containing FunctionContext instances)
        _bin_limit_lower (int): binary index (in all of the functions) of the lowest binary candidate for this file
        _bin_limit_upper (int): binary index (in all of the functions) of the uppmost binary candidate for this file        
        _lower_leftovers (int): size (in functions) of the lower "safety" gap (from a last valid match to the start of the file)
        _upper_leftovers (int): size (in functions) of the upper "safety" gap (from a last valid match to the end of the file)
        _match_sequences (list): Orderred list of match sequences in the file (containing MatchSequence instances)
        _lower_neighbours (dict): Dictionary containig failed matched "lower" adjacent neighbours: src index => (ea, is_match_neighbour)
        _upper_neighbours (dict): Dictionary containig failed matched "upper" adjacent neighbours: src index => (ea, is_match_neighbour)
        _unique_strings (list): List of unique string artefacts that were found in the source file
        _unique_consts (list): List of unique numeric const artefacts that were found in the source file
        _remain_size (int): number of source functions that are still to be matched
        _lower_match_ctx (FunctionContext): the lowest function that was matched till now
        _upper_match_ctx (FunctionContext): the uppmost function that was matched till now
        _locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when the FileMatch instance was created
        _lower_locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when expanding the match sequences downward
        _upper_locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when expanding the match sequences upward
    """
    def __init__(self, name, src_index_start, src_index_end, fuzzy_bin_functions_ctx, bin_limit_lower, bin_limit_upper, src_scope) :
        """Ctor() for creating a FileMatch instance according to initial binary bounds and initial anchors matched

        Args:
            name (str): name of the file (from the list of compiled files)
            src_index_start (int): source index of the first function in the source file
            src_index_end (int): source index of last function in the source file
            fuzzy_bin_functions_ctx (list): initial list of all candidate binary functions for this file (containing FunctionContext instances)
            bin_limit_lower (int): binary index (in all of the functions) of the lowest binary candidate for this file
            bin_limit_upper (int): binary index (in all of the functions) of the uppmost binary candidate for this file
            src_scope (int): number of src functions that are currently in scope of this file (differs between located and unlocated files) 
        """
        self._name               = name
        self._located            = src_scope == (src_index_end - src_index_start + 1)
        self._valid              = True
        self._src_index_start    = src_index_start
        self._src_index_end      = src_index_end
        self._bin_functions_ctx  = fuzzy_bin_functions_ctx
        self._bin_limit_lower    = bin_limit_lower
        self._bin_limit_upper    = bin_limit_upper
        self._lower_leftovers    = None
        self._upper_leftovers    = None
        # orderred list of matching sequences
        self._match_sequences    = []
        self._lower_neighbours   = {}
        self._upper_neighbours   = {}
        # list of unique artefacts
        self._unique_strings     = set()
        self._unique_consts      = set()

        # calculate the remaining size
        if self._located :
            inner_matches_indices = set(function_matches.keys()).intersection(range(self._src_index_start, self._src_index_end + 1))
            self._remain_size = self._src_index_end - self._src_index_start + 1
            self._remain_size -= len(inner_matches_indices)
        else :
            self._remain_size = src_scope
        # find the match boundaries
        self._lower_match_ctx = None
        self._upper_match_ctx = None

        # take ownership over the contained functions
        for bin_index, bin_ctx in enumerate(self._bin_functions_ctx if self._located else floating_bin_functions) :
            bin_ctx.linkFile(self)
            # can't use "matched()" because we are in a pre-updateHints phase
            if bin_ctx._ea in bin_matched_ea :
                if self._lower_match_ctx is None :
                    self._lower_match_ctx = bin_ctx
                self._upper_match_ctx = bin_ctx
                if self._located :
                    self._match_sequences.append(MatchSequence(bin_ctx))

        # take full ownership of functions between the two match indices (if they are indeed mine)
        self._locked_eas = set()
        self._lower_locked_eas = set()
        self._upper_locked_eas = set()
        if self._located :
            if self._lower_match_ctx is not None :
                bin_range = range(self._bin_functions_ctx.index(self._lower_match_ctx), self._bin_functions_ctx.index(self._upper_match_ctx) + 1)
                self._locked_eas.update(set(map(lambda x : self._bin_functions_ctx[x]._ea, bin_range)))
                for bin_index in bin_range :
                    bin_ctx = self._bin_functions_ctx[bin_index]
                    bin_ctx.linkFile(self)
                    # can't use "matched()" because we are in a pre-updateHints phase
                    if bin_ctx._ea in bin_matched_ea :
                        self._locked_eas.remove(bin_ctx._ea)

        # set up the leftovers using the matched index (if we have such)
        if self._lower_match_ctx is not None :
            self._lower_leftovers = self._lower_match_ctx._bin_index - self._bin_limit_lower
            self._upper_leftovers = self._bin_limit_upper - self._upper_match_ctx._bin_index
        
        # Check if can merge the initial sequences (wishful thinking)
        if self._located and self._lower_match_ctx is not None :
            self.cleanupMatches()

        # build the unique mappings
        all_strings = set()
        all_consts  = set()
        for src_ctx in src_functions_ctx[self._src_index_start : self._src_index_end + 1] :
            # strings
            self._unique_strings = self._unique_strings.union(src_ctx._strings.difference(all_strings))
            self._unique_strings = self._unique_strings.difference(all_strings.intersection(src_ctx._strings))
            all_strings = all_strings.union(src_ctx._strings)
            # (numeric) consts
            self._unique_consts = self._unique_consts.union(src_ctx._consts.difference(all_consts))
            self._unique_consts = self._unique_consts.difference(all_consts.intersection(src_ctx._consts))
            all_consts = all_consts.union(src_ctx._consts)

    def matched(self) :
        """Checks if the entire file was matched

        Return Value:
            True iff the entire file was matched
        """
        return self._remain_size == 0

    def valid(self):
        """Checks if the file exists

        Return value:
            return True iff the file exists
        """
        return self._valid

    def active(self) :
        """Checks if the given file is still active and waiting to be matched

        Return Value:
            return True iff the file is valid() and wasn't matched() yet
        """
        return self.valid() and not self.matched()

    def located(self):
        """Checks if the file was located already

        Return value:
            return True iff the file was located (matched atleast one function inside it)
        """
        return self._located

    def index(self, bin_ctx) :
        """Finds the index of the function's match sequence

        Assumptions:
            bin_ctx is contained in the file's list of binary functions

        Args:
            bin_ctx (FunctionContext): binary context of the function search for

        Return Value:
            Index of the function's match sequence (or None if failed)
        """
        if self._located :
            bin_index = self._bin_functions_ctx.index(bin_ctx)
            for seq_index, cur_seq in enumerate(self._match_sequences) :
                if self._bin_functions_ctx.index(cur_seq._bin_lower_ctx) <= bin_index and bin_index <= self._bin_functions_ctx.index(cur_seq._bin_upper_ctx) :
                    return seq_index
        return None

    def cleanupMatches(self, new_sequence = None) :
        """Cleans the list of match sequences, merging adjacent sequences if needed

        Args:
            new_sequence (MatchSequence, optional): newly added match sequence (None by default)
        """
        if new_sequence is not None :
            new_match_lower_index = self._bin_functions_ctx.index(new_sequence._bin_lower_ctx)
            new_match_upper_index = self._bin_functions_ctx.index(new_sequence._bin_upper_ctx)
        prev_match = self._match_sequences[0]
        prev_match_lower_index = self._bin_functions_ctx.index(prev_match._bin_lower_ctx)
        prev_match_upper_index = self._bin_functions_ctx.index(prev_match._bin_upper_ctx)
        new_sequence_list = [prev_match]
        # 1st case - the new one is before ours
        if new_sequence is not None and new_match_upper_index + 1 <= prev_match_lower_index :
            if new_match_upper_index + 1 == prev_match_lower_index :
                prev_match.merge(new_sequence, is_lower = True)
            else :
                new_sequence_list = [new_sequence, prev_match]
            new_sequence = None
        # Now scan the entire list
        for current_match in self._match_sequences[1:] :
            # can we insert the new sequence here?
            if new_sequence is not None and prev_match_upper_index + 1 == new_match_lower_index :
                prev_match.merge(new_sequence, is_lower = False)
                prev_match_upper_index = new_match_upper_index
                new_sequence = None
            current_match_lower_index = self._bin_functions_ctx.index(current_match._bin_lower_ctx)
            current_match_upper_index = self._bin_functions_ctx.index(current_match._bin_upper_ctx)
            if prev_match_upper_index + 1 == current_match_lower_index :
                prev_match.merge(current_match, is_lower = False)
            else :
                # Should we insert the sequence now?
                if new_sequence is not None :
                    if new_match_upper_index + 1 < current_match_lower_index :
                        new_sequence_list.append(new_sequence)
                        new_sequence = None
                    elif new_match_upper_index + 1 == current_match_lower_index :
                        current_match.merge(new_sequence, is_lower = True)
                        new_sequence = None
                prev_match = current_match
                new_sequence_list.append(prev_match)
            # update the indices
            prev_match_lower_index = current_match_lower_index
            prev_match_upper_index = current_match_upper_index
        # if we still have a new sequence, it means it is after the last one
        if new_sequence is not None :
            if prev_match_upper_index + 1 == new_match_lower_index :
                prev_match.merge(new_sequence, is_lower = False)
            else :
                new_sequence_list.append(new_sequence)
        # replace the lists
        self._match_sequences = new_sequence_list        

    def remove(self, src_index, bin_ctx) :
        """Removes the given function couple (src index, bin context) from the file's content

        Assumptions:
            bin_ctx is contained in the file's list of binary functions

        Args:
            src_index (int): (source) index of the removed (source) function
            bin_ctx (FunctionContext): (binary) context of the removed (binary) function
        """
        global src_unused_functions, floating_bin_functions
        # check if already removed
        if self._located and bin_ctx not in self._bin_functions_ctx :
            return
        # check the floating file
        if not self._located and bin_ctx not in floating_bin_functions :
            return
        # only the first "floating" file is the one that does the actions
        if not self._located and self != floating_files[0] :
            floating_files[0].remove(src_index, bin_ctx)
            return
        # set up the used binary_dictionary
        bin_ctxs = self._bin_functions_ctx if self._located else floating_bin_functions
        # locate the inner index
        bin_index = bin_ctxs.index(bin_ctx)
        # if the file wasn't yet located there is a reason to no simply do: "lower_part = not upper_part"
        upper_index = bin_ctxs.index(self._upper_match_ctx)
        lower_index = bin_ctxs.index(self._lower_match_ctx)
        upper_part = upper_index < bin_index
        lower_part = bin_index < lower_index
        # sanity check - more than the upper leftovers
        if upper_part and self._upper_leftovers is not None and len(bin_ctxs) - bin_index > self._upper_leftovers :
            logger.error("Sanity check failed on FileMatch.remove(): %d %d %d 0x%x %d", src_index, bin_index, len(bin_ctxs), bin_ctx._ea, self._upper_leftovers)
            debugPrintState(error = True)
        # sanity check - more than the lower leftovers
        elif lower_part and self._lower_leftovers is not None and bin_index + 1 > self._lower_leftovers :
            logger.error("Sanity check failed on FileMatch.remove(): %d %d 0x%x %d", src_index, bin_index, bin_ctx._ea, self._lower_leftovers)
            debugPrintState(error = True)
        # Now preform the update itself (changes according to the "type" of the file)
        if self._located :
            if upper_part :
                removed_funcs = self._bin_functions_ctx[bin_index:]
                self._bin_functions_ctx = self._bin_functions_ctx[:bin_index]
                if self._upper_leftovers is not None :
                    self._upper_leftovers -= len(removed_funcs)
                else :
                    self._bin_limit_upper -= len(removed_funcs)
            else :
                removed_funcs = self._bin_functions_ctx[:bin_index+1]
                self._bin_functions_ctx = self._bin_functions_ctx[bin_index+1:]
                if self._lower_leftovers is not None :
                    self._lower_leftovers -= len(removed_funcs)
                else :
                    self._bin_limit_lower += len(removed_funcs)
        # simply cut the leftovers if this match expanded the borders
        else :
            if upper_part :
                removed_funcs = floating_bin_functions[upper_index + 1 : bin_index + 1]
                self._upper_match_ctx = bin_ctx
                self._upper_leftovers -= len(removed_funcs)
            elif lower_part :
                removed_funcs = floating_bin_functions[bin_index : lower_index]
                self._lower_match_ctx = bin_ctx
                self._lower_leftovers -= len(removed_funcs)
            else :
                removed_funcs = []
            self._remain_size -= len(removed_funcs)
            # now purge out unused leftover functions
            if upper_part and self._lower_leftovers > self._remain_size :
                purge_size = self._lower_leftovers - self._remain_size
                removed_funcs += floating_bin_functions[ : purge_size]
                floating_bin_functions = floating_bin_functions[purge_size : ]
                self._lower_leftovers -= purge_size
                self._bin_limit_lower += purge_size
            if lower_part and self._upper_leftovers > self._remain_size :
                purge_size = self._upper_leftovers - self._remain_size
                removed_funcs += floating_bin_functions[-purge_size : ]
                floating_bin_functions = floating_bin_functions[ : -purge_size]
                self._upper_leftovers -= purge_size
                self._bin_limit_upper -= purge_size
            # We only need to expel the matched function, and that's it
            removed_funcs = [bin_ctx]
        # Now update all of the relevant functions that they are expelled from our file
        for removed_bin_ctx in removed_funcs :
            # expel from all relevant files (if I'm floating)
            for expel_file in [self] if self._located else floating_files :
                removed_bin_ctx.expel(expel_file)

    def match(self, src_index, bin_ctx) :
        """Notifies the file that the given function couple (src index, bin context) was matched

        Assumptions:
            bin_ctx is contained in the file's list of binary functions

        Args:
            src_index (int): (source) index of the matched (source) function
            bin_ctx (FunctionContext): (binary) context of the matched (binary) function
        """
        global src_unused_functions, floating_files, floating_bin_functions
        # check if this is an internal match or an external remove
        if src_index < self._src_index_start or self._src_index_end < src_index :
            self.remove(src_index, bin_ctx)
            return
        # rewire the floating functions back to our file (for adjustments)
        if not self._located :
            self._bin_functions_ctx = floating_bin_functions
        # special case for partial functions
        is_partial = bin_ctx.isPartial()
        # internal match could be: a) below lower bound b) above upper bound c) in the middle
        bin_index = self._bin_functions_ctx.index(bin_ctx) if not is_partial else None
        cleanup_matches = not is_partial
        link_files = set()
        expelled_funcs = []
        if len(self._match_sequences) != 0 :
            lower_match_index = self._bin_functions_ctx.index(self._lower_match_ctx)
            upper_match_index = self._bin_functions_ctx.index(self._upper_match_ctx)
        # case -1 - partial function (island)
        if is_partial :
            # nothing to be done at first
            pass
        # case 0 - no match yet
        elif not self._located :
            # check if we need to pass the role forward
            if floating_files.index(self) == 0 and len(floating_files) > 1 :
                floating_files[1]._lower_match_ctx = self._lower_match_ctx
                floating_files[1]._upper_match_ctx = self._upper_match_ctx
                floating_files[1]._lower_leftovers = self._lower_leftovers
                floating_files[1]._upper_leftovers = self._upper_leftovers
                floating_files[1]._bin_limit_lower = self._bin_limit_lower
                floating_files[1]._bin_limit_upper = self._bin_limit_upper
            # No, just take the information we need form him
            else :
                self._bin_limit_lower = floating_files[0]._bin_limit_lower
                self._bin_limit_upper = floating_files[0]._bin_limit_upper
            floating_files.remove(self)
            self._lower_match_ctx = bin_ctx
            self._upper_match_ctx = bin_ctx
            self._match_sequences.append(MatchSequence(bin_ctx))
            # we can finaly set the leftovers' values
            self._lower_leftovers = self._lower_match_ctx._bin_index - self._bin_limit_lower
            self._upper_leftovers = self._bin_limit_upper - self._upper_match_ctx._bin_index
            # tell the match that it's mine
            link_files.add(self._bin_functions_ctx[bin_index])
            # mark myself as located
            self._located = True
            self._remain_size = self._src_index_end - self._src_index_start + 1
            cleanup_matches = False
            # now adjust the leftovers (and bin functions) according to (potential) prior matches
            for lower_leftovers in xrange(1, self._lower_leftovers) :
                if self._bin_functions_ctx[bin_index - lower_leftovers]._ea in bin_matched_ea :
                    self._lower_leftovers = lower_leftovers - 1
                    break
            for upper_leftovers in xrange(1, self._upper_leftovers) :
                if self._bin_functions_ctx[bin_index + upper_leftovers]._ea in bin_matched_ea :
                    self._upper_leftovers = upper_leftovers - 1
                    break
            # build an initial list of expelled functions
            expelled_funcs += self._bin_functions_ctx[ : bin_index - self._lower_leftovers]
            expelled_funcs += self._bin_functions_ctx[bin_index + self._upper_leftovers + 1 : ]
            self._bin_functions_ctx = self._bin_functions_ctx[bin_index - self._lower_leftovers : bin_index + self._upper_leftovers + 1]
        # case a
        elif bin_index < lower_match_index :
            self._lower_leftovers -= lower_match_index - bin_index
            self._lower_locked_eas.update(map(lambda ctx : ctx._ea, self._bin_functions_ctx[bin_index + 1 : lower_match_index]))
            link_files.update(self._bin_functions_ctx[bin_index : lower_match_index])
            self._lower_match_ctx = bin_ctx
        # case b
        elif bin_index > upper_match_index :
            self._upper_leftovers -= bin_index - upper_match_index
            self._upper_locked_eas.update(map(lambda ctx : ctx._ea, self._bin_functions_ctx[upper_match_index + 1 : bin_index]))
            link_files.update(self._bin_functions_ctx[upper_match_index + 1 : bin_index + 1])
            self._upper_match_ctx = bin_ctx
        # case c
        else :
            link_files.add(self._bin_functions_ctx[bin_index])
            if bin_ctx._ea in self._locked_eas :
                self._locked_eas.remove(bin_ctx._ea)
            if bin_ctx._ea in self._upper_locked_eas :
                self._upper_locked_eas.remove(bin_ctx._ea)
            if bin_ctx._ea in self._lower_locked_eas :
                self._lower_locked_eas.remove(bin_ctx._ea)
        # we have one less function to handle
        self._remain_size -= 1

        # shorten the upper leftovers
        if self._upper_leftovers > self._remain_size - (len(self._locked_eas) + len(self._lower_locked_eas)):
            delta = self._upper_leftovers - (self._remain_size - (len(self._locked_eas) + len(self._lower_locked_eas)))
            self._upper_leftovers -= delta
            expelled_funcs += self._bin_functions_ctx[-delta:]
            self._bin_functions_ctx = self._bin_functions_ctx[:-delta]
        # shorten the lower leftovers
        if self._lower_leftovers > self._remain_size - (len(self._locked_eas) + len(self._upper_locked_eas)) :
            delta = self._lower_leftovers - (self._remain_size - (len(self._locked_eas) + len(self._upper_locked_eas)))
            self._lower_leftovers -= delta
            expelled_funcs += self._bin_functions_ctx[:delta]
            self._bin_functions_ctx = self._bin_functions_ctx[delta:]

        # should now find a suitable sequence for it
        if cleanup_matches:
            self.cleanupMatches(MatchSequence(bin_ctx))

        # Now link all of the files (atomically)
        for linked_ctx in link_files :
            linked_ctx.linkFile(self)

        # Now expell all of the functions
        for expelled_ctx in expelled_funcs :
            expelled_ctx.expel(self)

        # check if we finished all binaries, and purge out the remainig sources
        if len(filter(lambda ctx : not ctx.matched(), self._bin_functions_ctx)) == 0 :
            unused_funcs = filter(lambda x : x not in function_matches, range(self._src_index_start, self._src_index_end + 1))
            if len(unused_funcs) > 0 :
                src_unused_functions.update(unused_funcs)
                for src_index in unused_funcs :
                    src_functions_ctx[src_index].disable()
                self._remain_size = 0
                # adjust the limits of the floating file
                if len(floating_files) > 0 :
                    floating_file = floating_files[0]
                    floating_file._remain_size -= len(unused_funcs)
                    expelled_funcs = floating_bin_functions[ : len(unused_funcs)] + floating_bin_functions[-len(unused_funcs) : ]
                    floating_bin_functions = floating_bin_functions[len(unused_funcs) : -len(unused_funcs)]
                    floating_file._lower_leftovers -= len(unused_funcs)
                    floating_file._upper_leftovers -= len(unused_funcs)
                    floating_file._bin_limit_lower += len(unused_funcs)
                    floating_file._bin_limit_upper -= len(unused_funcs)
                    # expell & disable the functions
                    for expelled_ctx in expelled_funcs :
                        for floating in floating_files :
                            expelled_ctx.expel(floating)
            
    def attemptMatches(self) :
        """Attempt to match new functions in the scope of the file

        Return Value:
            True iff matched atleast one function
        """
        match_result = False
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return match_result
        # don't work on unlocated files
        if not self.located():
            return match_result
        # check for a full (src + bin) singleton
        if self._remain_size == 1 and len(filter(lambda ctx : ctx.active(), self._bin_functions_ctx)) == 1 :
            # we have a singleton - check if it has hints / is it locked
            singleton_ctx = filter(lambda ctx : ctx.active(), self._bin_functions_ctx)[0]
            # if used, just match it
            if singleton_ctx.isHinted() or (0 < self._bin_functions_ctx.index(singleton_ctx) and self._bin_functions_ctx.index(singleton_ctx) < len(self._bin_functions_ctx) - 1) :
                singleton_index = filter(lambda x : x not in function_matches, xrange(self._src_index_start, self._src_index_end + 1))[0]
                match_result = declareMatch(singleton_index, singleton_ctx._ea, REASON_FILE_SINGLETON) or match_result
        # check for a (locked) bin singleton
        if len(filter(lambda ctx : ctx.active(), self._bin_functions_ctx)) == 1 :
            singleton_ctx = filter(lambda ctx : ctx.active(), self._bin_functions_ctx)[0]
            # indeed locked
            if 0 < self._bin_functions_ctx.index(singleton_ctx) and self._bin_functions_ctx.index(singleton_ctx) < len(self._bin_functions_ctx) - 1 :
                singleton_index = filter(lambda x : x not in function_matches, range(self._src_index_start, self._src_index_end + 1))[0]
                # try to match it to all remaining source options, and pick the best one
                best_score = None
                best_src_index = None
                prev_match_index = bin_matched_ea[self._bin_functions_ctx[self._bin_functions_ctx.index(singleton_ctx) - 1]._ea]
                for src_index in filter(lambda x : x not in function_matches, range(self._src_index_start, self._src_index_end + 1)) :
                    next_match_index = bin_matched_ea[self._bin_functions_ctx[self._bin_functions_ctx.index(singleton_ctx) + 1]._ea]
                    # filter it, before giving it a matching score
                    if not src_functions_ctx[src_index].isValidCandidate(singleton_ctx) :
                        continue
                    cur_score = src_functions_ctx[src_index].compare(singleton_ctx, logger)
                    # don't forget to boost neighbours
                    cur_score += LOCATION_BOOST_SCORE * [prev_match_index + 1, next_match_index - 1].count(src_index)
                    if best_score is None or cur_score > best_score :
                        best_score = cur_score
                        best_src_index = src_index
                    elif best_score is not None and cur_score == best_score :
                        best_src_index = None # we have a tie
                    prev_match_index = next_match_index
                # check if we made it
                if best_src_index is not None :
                    match_result = declareMatch(best_src_index, singleton_ctx._ea, REASON_FILE_SINGLETON) or match_result
        # scan the sequences in search for a potential match
        if len(self._match_sequences) > 1 :
            for sequence in self._match_sequences :
                # prefer internal matches
                if sequence == self._match_sequences[0] :
                    match_result = self.attemptMatchEnd(sequence) or match_result
                elif sequence == self._match_sequences[-1] :
                    match_result = self.attemptMatchStart(sequence) or match_result
                # normal case
                else :
                    match_result = self.attemptMatchStart(sequence) or match_result
                    match_result = self.attemptMatchEnd(sequence) or match_result
        # now check the dangerous leftovers zone
        if len(self._match_sequences) > 0 :
            match_result = self.attemptMatchStart(self._match_sequences[0]) or match_result
            match_result = self.attemptMatchEnd(self._match_sequences[-1]) or match_result
        # for a full size match, check the file borders too
        if len(self._bin_functions_ctx) == (self._src_index_end - self._src_index_start + 1) :
            # file start
            self._lower_neighbours[self._src_index_start] = (self._bin_functions_ctx[0]._ea, False)
            is_match = matchAttempt(self._src_index_start, self._bin_functions_ctx[0]._ea, file_match = self)
            match_result = is_match or match_result
            # file end
            self._upper_neighbours[self._src_index_end] = (self._bin_functions_ctx[-1]._ea, False)
            is_match = matchAttempt(self._src_index_end, self._bin_functions_ctx[-1]._ea, file_match = self)
            match_result = is_match or match_result
        # Return the result
        return match_result

    def attemptMatchStart(self, sequence) :
        """Attempt to match a new function from the start (going downwards) of the given match sequence

        Args:
            sequence (MatchSequence): given match sequence that we are trying to expand downward

        Return Value:
            True iff matched a function
        """
        matched_bin_index = self._bin_functions_ctx.index(sequence._bin_lower_ctx)
        # can't extend the binary downard
        if matched_bin_index == 0 :
            return False    
        matched_src_index = sequence._bin_lower_ctx.match()._src_index
        # can't extend the source downard
        if matched_src_index == self._src_index_start :
            return False
        self._lower_neighbours[matched_src_index - 1] = (self._bin_functions_ctx[matched_bin_index - 1]._ea, True)
        if matchAttempt(matched_src_index - 1, self._bin_functions_ctx[matched_bin_index - 1]._ea, file_match = self) :
            return True
        return False

    def attemptMatchEnd(self, sequence) :
        """Attempt to match a new function from the end (going upward) of the given match sequence

        Args:
            sequence (MatchSequence): given match sequence that we are trying to expand upward

        Return Value:
            True iff matched a function
        """
        matched_bin_index = self._bin_functions_ctx.index(sequence._bin_upper_ctx)
        # can't extend the binary upward
        if matched_bin_index == len(self._bin_functions_ctx) - 1 :
            return False
        # can't extend the source upward
        matched_src_index = sequence._bin_upper_ctx.match()._src_index
        if matched_src_index == self._src_index_end :
            return False
        self._upper_neighbours[matched_src_index + 1] = (self._bin_functions_ctx[matched_bin_index + 1]._ea, True)
        if matchAttempt(matched_src_index + 1, self._bin_functions_ctx[matched_bin_index + 1]._ea, file_match = self) :
            return True
        return False

    def attemptFindFileHints(self) :
        """Attempt to find matches using file name hint strings"""
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return
        # check if there is a hint pointing at my file
        our_str_hint = None
        for file_hint in str_file_hints :
            if self._name.split(os.path.sep)[-1].split('.')[0] == file_hint.split('.')[0] :
                our_str_hint = file_hint
                break
        if our_str_hint is None :
            return
        # now try to match every hinted source function, with every hinted binary functions
        for src_index in xrange(self._src_index_start, self._src_index_end + 1) :
            src_ctx = src_functions_ctx[src_index]
            # skip matched / unhinted functions
            if not src_ctx.active() or not src_ctx.hasFileHint() :
                return
            # find the hinted binary candidates
            for bin_ctx in (self._bin_functions_ctx if self._located else floating_bin_functions) :
                # skip unhinted functions
                if our_str_hint not in bin_ctx._strings :
                    continue
                # filter it, before giving it a matching score
                if not src_ctx.isValidCandidate(bin_ctx) :
                    continue
                # now attempt to score them (the boost is embedded in the scoring of the matched hint string)
                score = src_ctx.compare(bin_ctx, logger)
                # record the result (the final decision about it will be received later)
                recordRoundMatchAttempt(src_index, bin_ctx._ea, 0, score, REASON_FILE_HINT)

    def attemptFindAgents(self) :
        """Attempt to find "agents" functions according to unique file artefacts"""
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return
        # scan all of the src functions, in search for an agent
        for src_index in xrange(self._src_index_start, self._src_index_end + 1) :
            # skip matched functions
            if src_index in function_matches :
                continue
            # check if this is an agent
            src_candidate = src_functions_ctx[src_index]
            is_string, threshold, agent_criteria = isAgent(src_candidate, self._unique_strings, self._unique_consts, logger)
            if agent_criteria is None :
                continue
            # Now scan the binary functions for a possible match
            for bin_ctx in (self._bin_functions_ctx if self._located else floating_bin_functions) :
                # skip matched functions
                if not bin_ctx.active() :
                    continue
                # check if the same criteria works
                if len(set(agent_criteria).intersection(bin_ctx._strings if is_string else bin_ctx._consts)) < threshold :
                    continue
                # be careful with the score boost
                effective_unique_strings = self._unique_strings
                effective_unique_consts  = self._unique_consts
                for file_options in bin_ctx._files :
                    if file_options == self :
                        continue
                    effective_unique_strings = effective_unique_strings.difference(file_options._unique_strings)
                    effective_unique_consts  = effective_unique_consts.difference(file_options._unique_consts)
                double_is_string, double_threshold, double_agent_criteria = isAgent(src_candidate, effective_unique_strings, effective_unique_consts, logger)
                if double_agent_criteria is None or set(agent_criteria).intersection(double_agent_criteria) < double_threshold :
                    score_boost = 0
                else :
                    score_boost = AGENT_BOOST_SCORE
                # filter it, before giving it a matching score
                if not src_candidate.isValidCandidate(bin_ctx) :
                    continue
                # now attempt to score them
                score = src_candidate.compare(bin_ctx, logger)
                # record the result (the final decision about it will be received later)
                recordRoundMatchAttempt(src_index, bin_ctx._ea, score_boost, score + score_boost, REASON_AGENT)

    def attemptMatchSwallows(self) :
        """Attempt to match new functions by searching for swallowd functions (islands)

        Return Value:
            True iff matched atleast one function
        """
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return False
        # scan the src gaps this time
        src_index = self._src_index_start
        first_matched = False
        while src_index <= self._src_index_end :
            # skip if matched
            if src_index in function_matches :
                src_index += 1
                first_matched = True
                continue
            if not first_matched :
                src_index += 1
                continue
            gap_index_start = src_index
            gap_index_end = None
            # now search for the gap's end
            src_index += 1
            while src_index <= self._src_index_end :
                if src_index in function_matches :
                    gap_index_end = src_index
                    break
                src_index += 1
            # the gap did not end
            if gap_index_end is None :
                return False
            # find the bin size
            gap_bin_start = function_matches[gap_index_start - 1]
            gap_bin_end   = function_matches[gap_index_end]
            # try to search for a swallow
            if self.attemptMatchSwallow(gap_index_start, gap_index_end - 1, gap_bin_start, gap_bin_end) :
                return True
        # Return the result
        return False

    def attemptMatchSwallow(self, src_index_start, src_index_end, lower_bound, upper_bound) :
        """Attempt to match new functions by searching for swallowd functions (islands) in a given range

        Args:
            src_index_start (int): start (source) index of an unmatched (source) gap
            src_index_end (int): end (source) index of an unmatched (source) gap
            lower_bound (int): ea of the lower bound of the gap in the binary address space
            upper_bound (int): ea of the upper bound of the gap in the binary address space

        Return Value:
            True iff matched atleast one function
        """
        gap_size = upper_bound - lower_bound
        # sanity check - should not happen
        if gap_size <= 0 :
            return False
        # check all of the options in the source gap
        for src_index in xrange(src_index_start, src_index_end + 1) :
            # check for a single xref source function
            src_candidate_ctx = src_functions_ctx[src_index]
            if len(src_candidate_ctx._xrefs) != 1 :
                continue
            # check if the xref was matched already (we can't advance otherwise)
            src_parent = list(src_candidate_ctx._xrefs)[0]
            if not src_parent.matched() :
                continue
            # now check if there is a floating chunk inside this gap
            bin_parent = src_parent.match()
            # make sure (sanity check) that bin_parent is not inside our gap
            if lower_bound <= bin_parent._ea and bin_parent._ea <= upper_bound :
                continue
            island_blocks = searchIslands(bin_parent._ea, lower_bound, upper_bound)
            # Failed to find a match
            if island_blocks is None :
                return False
            # We have a list of linked external blocks, that are linked to the parent function, and were found in our gap => Jackpot
            island_ctx = analyzeIslandFunction(island_blocks)
            # Fix it's externals
            bin_internal_calls = []
            bin_external_calls = []
            for call_ea in island_ctx._calls :
                if call_ea in bin_functions_ctx.keys() :
                    bin_internal_calls.append(bin_functions_ctx[call_ea])
                else :
                    bin_external_calls.append(call_ea)
            island_ctx._calls = bin_internal_calls
            island_ctx._externals = bin_external_calls
            bin_external_functions.update(bin_external_calls)
            # score it up and check for a match (no need to filter this option, it's a swallow)
            score = island_ctx.compare(src_candidate_ctx, logger)
            if src_index == src_index_start or src_index == src_index_end :
                score += LOCATION_BOOST_SCORE
            if score >= MINIMAL_ISLAND_SCORE :
                bin_functions_ctx[island_ctx._ea] = island_ctx
                declareMatch(src_candidate_ctx._src_index, island_ctx._ea, REASON_SWALLOW)
                return True
        return False

def updateHints(src_index, func_ea) :
    """Update our knowledge using hints derived from the recent matched function

    Args:
        src_index (int): (source) index of the matched (source) function
        func_ea (int): ea of the (binary) matched function
    """
    global changed_functions, bin_matched_ea, call_hints_records, src_functions_ctx, bin_functions_ctx

    # record the match (also tells my followers tham I'm taken)
    src_functions_ctx[src_index].declareMatch(bin_functions_ctx[func_ea])
    bin_functions_ctx[func_ea].declareMatch(src_functions_ctx[src_index])

    # record the instruction ratio sample
    if not bin_functions_ctx[func_ea].isPartial() :
        recordInstrRatio(src_functions_ctx[src_index]._instrs, bin_functions_ctx[func_ea]._instrs)

    # function calls
    bin_calls = filter(lambda x : x.active(), bin_functions_ctx[func_ea]._calls)
    src_calls = filter(lambda x : x.active(), src_functions_ctx[src_index]._calls)
    if len(bin_calls) > 0 and len(src_calls) > 0 :
        # can only continue if this condition does NOT apply because it will cause duplicate "single call" matches
        if not (len(bin_calls) > 1 and len(src_calls) == 1) :
            call_hints_records.append((src_calls, bin_calls, src_functions_ctx[src_index], bin_functions_ctx[func_ea], False))
            for bin_ctx in bin_calls :
                bin_ctx.addHints(filter(lambda x : x.isValidCandidate(bin_ctx), src_calls), True)
        for src_ctx in src_calls :
            if src_ctx._src_index not in changed_functions :
                changed_functions[src_ctx._src_index] = set()
            changed_functions[src_ctx._src_index].update(filter(lambda x : src_ctx.isValidCandidate(x), bin_calls))
    # function xrefs
    bin_xrefs = filter(lambda x : x.active(), bin_functions_ctx[func_ea]._xrefs)
    src_xrefs = filter(lambda x : x.active(), src_functions_ctx[src_index]._xrefs)
    if len(bin_xrefs) > 0 and len(src_xrefs) > 0 :
        # can only continue if this condition does NOT apply because it will cause duplicate "single call" matches
        if not (len(bin_xrefs) > 1 and len(src_xrefs) == 1) :
            for bin_ctx in bin_xrefs :
                bin_ctx.addHints(filter(lambda x : x.isValidCandidate(bin_ctx), src_xrefs), False)
        for src_ctx in src_xrefs :
            if src_ctx._src_index not in changed_functions :
                changed_functions[src_ctx._src_index] = set()
            changed_functions[src_ctx._src_index].update(filter(lambda x : src_ctx.isValidCandidate(x), bin_xrefs))
    # external functions
    bin_exts = filter(lambda ea : ea not in bin_matched_ea, bin_functions_ctx[func_ea]._externals)
    src_exts = filter(lambda x : x.active(), src_functions_ctx[src_index]._externals)
    if len(bin_exts) > 0 and len(src_exts) > 0 :
        call_hints_records.append((src_exts, bin_exts, src_functions_ctx[src_index], bin_functions_ctx[func_ea], True))
        # can't continue because it will cause duplicate matches for the same binary
        if len(bin_exts) == 1 and len(src_exts) > 1 :
            return
        for src_ext in src_exts :
            src_ext.addHints(bin_exts)
            # Check for matches
            matched_ea = src_ext.match()
            if matched_ea is not None and matched_ea not in bin_matched_ea:
                bin_matched_ea[matched_ea] = src_external_functions[src_ext._name]
                src_ext._ea = matched_ea
                logger.info("Matched external function: %s == 0x%x (%s)", src_ext._name, matched_ea, sark.Function(matched_ea).name)

def declareMatch(src_index, func_ea, reason) :
    """Officially declare a match of a source function to code that starts with the given binary ea

    Args:
        src_index (int): (source) index of the matched (source) function
        func_ea (int): ea of the matched (binary) function (maybe an island)
        reason (enum): matching reason, taken from the string enum options
    """
    global changed_functions, anchor_hints, bin_matched_ea, src_functions_ctx, matching_reason

    function = sark.Function(func_ea)
    is_anchor = reason == REASON_ANCHOR
    # Sanitation logic that uses contexts (non available in anchor phase)
    if not is_anchor:
        src_candidate = src_functions_ctx[src_index]
        bin_candidate = bin_functions_ctx[func_ea]
        # double check the match
        if not bin_candidate.isPartial() and not src_candidate.isValidCandidate(bin_candidate) :
            logger.error("Cancelled an invalid match: %s (%d) != 0x%x (%s)", src_candidate._name, src_candidate._src_index, bin_candidate._ea, function.name)
            debugPrintState(error = True)
        # no need to declare it twice for anchors
        logger.info("Declared a match: %s (%d) == 0x%x (%s)", src_functions_list[src_index], src_index, func_ea, function.name)
        logger.debug("Matching reason is: %s", reason)

    # debug sanity checks
    if function.name != src_functions_list[src_index] :
        # check if this is an unnamed IDA functions
        if function.name.startswith("sub_") :
            logger.debug("Matched to an unknown function: %s (%d) == 0x%x (%s)", src_functions_list[src_index], src_index, func_ea, function.name)
        else :
            logger.debug("Probably matched a False Positive: %s (%d) == 0x%x (%s)", src_functions_list[src_index], src_index, func_ea, function.name)

    # register the match
    function_matches[src_index] = func_ea
    bin_matched_ea[func_ea]     = src_index
    matching_reason[src_index]  = reason

    # no need to keep track of the source function any more
    if src_index in changed_functions :
        changed_functions.pop(src_index)
    if src_index in once_seen_couples_src :
        once_seen_couples_src.pop(src_index)
    if func_ea in once_seen_couples_bin :
        once_seen_couples_bin.pop(func_ea)

    # can't continue if an anchor function (the data structures were not built yet)
    if is_anchor :
        anchor_hints.append((src_index, func_ea))
        return

    # update the hints now, no need to wait
    updateHints(src_index, func_ea)

    # update all of the relevant match files
    file_list = list(bin_functions_ctx[func_ea]._files) if not bin_candidate.isPartial() else [src_functions_ctx[src_index]._file]
    for match_file in file_list :
        # winner file
        if match_file._src_index_start <= src_index and src_index <= match_file._src_index_end :
            match_file.match(src_index, bin_functions_ctx[func_ea])
        # loser file
        else :
            match_file.remove(src_index, bin_functions_ctx[func_ea])

def roundMatchResults() :
    """Declares the winners of the match round, and prepares for the next round

    Return Value:
        True iff found at least 1 matching couple
    """
    global match_round_candidates, match_round_src_index, match_round_bin_ea, match_round_losers

    declared_match = False
    matched_src_index = set()
    matched_bin_ea    = set()
    # scan all of the records and decide which will be a real match
    for match_record in match_round_candidates :
        # 0. Prepare the variables for easy use
        src_index = match_record['src_index']
        func_ea   = match_record['func_ea']
        src_candidate = src_functions_ctx[src_index]
        bin_candidate = bin_functions_ctx[func_ea]
        logger.debug("Round match attempt: %s (%d) vs %s (0x%x): %f (+%f = %f)" % (src_candidate._name, src_index, bin_candidate._name, bin_candidate._ea, 
                                                                                            match_record['score'] - match_record['boost'], match_record['boost'], match_record['score']))
        # 1. Make sure it is a valid candidate
        if not src_candidate.isValidCandidate(bin_candidate) :
            continue
        # 2. Are we high enough for a match?
        elif match_record['score'] < MINIMAL_MATCH_SCORE :
            # record the loser
            match_round_losers.append(match_record)
        # 3. We have a match :)
        else :
            # actually match the couple
            logger.info("Matching in a round match according to score: %f (%f)", match_record['score'] - match_record['boost'], match_record['score'])
            declareMatch(src_index, func_ea, match_record['reason'])
            declared_match = True
            # store them for a later filter
            matched_src_index.add(src_index)
            matched_bin_ea.add(func_ea)

    # filter the losers
    final_loser_list = []
    for loser_record in match_round_losers :
        if loser_record['src_index'] in matched_src_index or loser_record['func_ea'] in matched_bin_ea :
            continue
        # check for validity
        if not src_functions_ctx[loser_record['src_index']].isValidCandidate(bin_functions_ctx[loser_record['func_ea']]) :
            continue
        final_loser_list.append((loser_record['src_index'], loser_record['func_ea']))
    match_round_losers = final_loser_list

    # empty the rest of the data structures
    match_round_candidates = []
    match_round_src_index  = {}
    match_round_bin_ea     = {}

    # return the final results
    return declared_match

def recordRoundMatchAttempt(src_index, func_ea, score_boost, score, reason) :
    """Records a match attempt into the round's records

    Args:
        src_index (int): (source) index of the candidate (source) function
        func_ea (int): ea of the candidate (binary) function (can't be an island)
        score_boost (int): score boost given to the match attempt because of it's circumstances
        score (int): final matching score (including the score_boost) 
        reason (enum): matching reason, taken from the string enum
    """
    global match_round_candidates, match_round_src_index, match_round_bin_ea, match_round_losers

    match_record =  {
                        'src_index' : src_index,
                        'func_ea'   : func_ea,
                        'boost'     : score_boost,
                        'score'     : score,
                        'gap-safe'  : True,
                        'gap'       : None,
                        'reason'    : reason,
                    }

    # check using the src_index
    prev_record = None
    if src_index not in match_round_src_index :
        match_round_src_index[src_index] = match_record
        match_round_candidates.append(match_record)
    else :
        prev_record = match_round_src_index[src_index]
        # toss duplicates (both ways)
        if prev_record['func_ea'] == match_record['func_ea'] :
            if match_record['score'] <= prev_record['score'] :
                return
            # be safe with the gaps
            elif prev_record['gap-safe'] :
                # simply adjust it's score (no need to throw him out)
                prev_record['score']  = match_record['score']
                prev_record['boost']  = match_record['boost']
                prev_record['reason'] = match_record['reason']
                return
            # still the winner in the binary match - had a gap in the binary or the source
            elif match_round_bin_ea[func_ea] == prev_record :
                # If we won the gap
                if abs(score - prev_record['gap']) > SAFTEY_GAP_SCORE :
                    prev_record['gap-safe'] = True
                    prev_record['gap'] = None
                    # revive us back
                    match_round_candidates.append(prev_record)
                    match_round_losers.remove(prev_record)
                # always preform the update
                prev_record['score']  = match_record['score']
                prev_record['boost']  = match_record['boost']
                prev_record['reason'] = match_record['reason']
                return
            # lost the binary match - match_round_bin_ea[func_ea] != prev_record
            else :
                prev_bin_record = match_round_bin_ea[func_ea]
                # If we won the gap
                if abs(score - match_round_bin_ea[func_ea]['score']) > SAFTEY_GAP_SCORE :
                    prev_record['gap-safe'] = True
                    prev_record['gap'] = None
                    # revive us back (and throw the previous winner)
                    if prev_bin_record['gap-safe'] :
                        prev_bin_record['gap-safe'] = False
                        match_round_candidates.remove(prev_bin_record)
                        match_round_losers.append(prev_bin_record)
                    match_round_bin_ea[func_ea] = prev_record
                    match_round_candidates.append(prev_record)
                    match_round_losers.remove(prev_record)
                # check if we are now back the winners of the binary match
                elif prev_bin_record['score'] < score :
                    match_round_bin_ea[func_ea] = prev_record
                    prev_record['gap'] = prev_bin_record['score']
                    if prev_bin_record['gap-safe'] :
                        prev_bin_record['gap-safe'] = False
                        match_round_candidates.remove(prev_bin_record)
                        match_round_losers.append(prev_bin_record)
                # always preform the update
                prev_record['score']  = match_record['score']
                prev_record['boost']  = match_record['boost']
                prev_record['reason'] = match_record['reason']
        # check if our candidate even needs to compete
        if score + SAFTEY_GAP_SCORE < prev_record['score'] :
            # tough luck, we should get rejected
            match_record['gap-safe'] = False
            match_round_losers.append(match_record)
        # both of us lost
        elif abs(score - prev_record['score']) <= SAFTEY_GAP_SCORE :
            match_record['gap-safe'] = False
            match_round_losers.append(match_record)
            # remove him only once
            if prev_record['gap-safe'] :
                prev_record['gap-safe'] = False
                match_round_candidates.remove(prev_record)
                match_round_losers.append(prev_record)
            # check who will be marked as the best loser
            if prev_record['score'] < score :
                match_round_src_index[src_index] = match_record
                match_record['gap'] = prev_record['score']
            elif prev_record['gap'] is None :
                prev_record['gap'] = score
            else :
                prev_record['gap'] = max(score, prev_record['gap'])
        # we won, and we should remember the seen record
        else :
            match_round_src_index[src_index] = match_record
            match_round_candidates.append(match_record)
            # remove him only once
            if prev_record['gap-safe'] :
                prev_record['gap-safe'] = False
                match_round_candidates.remove(prev_record)
                match_round_losers.append(prev_record)
            
    # check using the func_ea
    if func_ea not in match_round_bin_ea :
        match_round_bin_ea[func_ea] = match_record
        # we are in, or we lost, in both cases we shouldn't be added in
    else :
        prev_record = match_round_bin_ea[func_ea]
        # check if our candidate even needs to compete
        if score + SAFTEY_GAP_SCORE < prev_record['score'] :
            # tough luck, we should get rejected
            if match_record['gap-safe'] :
                match_record['gap-safe'] = False
                match_round_candidates.remove(match_record)
                match_round_losers.append(match_record)
        # both of us lost
        elif abs(score - prev_record['score']) <= SAFTEY_GAP_SCORE :
            # remove him only once
            if prev_record['gap-safe'] :
                prev_record['gap-safe'] = False
                match_round_candidates.remove(prev_record)
                match_round_losers.append(prev_record)
            # remove me only once
            if match_record['gap-safe'] :
                match_record['gap-safe'] = False
                match_round_candidates.remove(match_record)
                match_round_losers.append(match_record)
            # check who will be marked as the best loser
            if prev_record['score'] < score :
                match_round_bin_ea[func_ea] = match_record
                match_record['gap'] = prev_record['score']
            elif prev_record['gap'] is None :
                prev_record['gap'] = score
            else :
                prev_record['gap'] = max(score, prev_record['gap'])
        # we won, and we should remember the seen record
        else :
            match_round_bin_ea[func_ea] = match_record
            # remove him only once
            if prev_record['gap-safe'] :
                prev_record['gap-safe'] = False
                match_round_candidates.remove(prev_record)
                match_round_losers.append(prev_record)
            # don't add me twice, and don't add me if failed before
    
def matchAttempt(src_index, func_ea, file_match = None) :
    """Attempt to match a source function to code that starts with the given binary ea

    Args:
        src_index (int): (source) index of the candidate (source) function
        func_ea (int): ea of the candidate (binary) function (can't be an island)
        file_match (FileMatch, optional): file in which we are currently trying a geographical match (None by default)
    """
    # sanity checks
    if src_index < 0 or len(src_functions_ctx) <= src_index or src_index in function_matches or func_ea in bin_matched_ea :
        return False
    src_candidate = src_functions_ctx[src_index]
    bin_candidate = bin_functions_ctx[func_ea]
    # filter it before giving it a score
    if not src_candidate.isValidCandidate(bin_candidate) :
        return False
    score = src_candidate.compare(bin_candidate, logger)
    score_boost = 0
    neighbour_match = False
    # lower neighbour
    if file_match is not None and src_index in file_match._lower_neighbours and file_match._lower_neighbours[src_index][0] == func_ea :
        score_boost += LOCATION_BOOST_SCORE
        neighbour_match = file_match._lower_neighbours[src_index][1]
    # upper neighbour
    if file_match is not None and src_index in file_match._upper_neighbours and file_match._upper_neighbours[src_index][0] == func_ea :
        score_boost += LOCATION_BOOST_SCORE
        neighbour_match = file_match._upper_neighbours[src_index][1]
    # handle the functions on the file's edge:
    # 1. File's edge when |bin| == |src|
    # 2. Lower edge when previous (adjacent) file was completed
    # 3. Upper edge when next (adjacent) file was completed
    if file_match is not None and neighbour_match and src_index in [file_match._src_index_start, file_match._src_index_end] and \
            (len(file_match._bin_functions_ctx) == (file_match._src_index_end - file_match._src_index_start + 1) or \
            (src_index == file_match._src_index_start and \
                    file_match._lower_leftovers < file_match._remain_size - (len(file_match._locked_eas) + len(file_match._upper_locked_eas))) or \
            (src_index == file_match._src_index_end and \
                    file_match._upper_leftovers < file_match._remain_size - (len(file_match._locked_eas) + len(file_match._lower_locked_eas)))) :
        score_boost += LOCATION_BOOST_SCORE
    # triple the bonus if both apply
    if score_boost >= 2 * LOCATION_BOOST_SCORE :
        score_boost += LOCATION_BOOST_SCORE 
    logger.debug("%s (%d) vs %s (0x%x): %f (+%f = %f)" % (src_candidate._name, src_index, bin_candidate._name, bin_candidate._ea, score, score_boost, score + score_boost))
    # record the result (the final decision about it will be received later)
    recordRoundMatchAttempt(src_index, func_ea, score_boost, score + score_boost, REASON_NEIGHBOUR if score_boost > 0 else REASON_SCORE)
    # now behave as we expect (unless a better record will win the race)
    if score + score_boost >= MINIMAL_MATCH_SCORE :
        return True
    else :
        # skip bad neighbours
        if file_match is not None and score <= MINIMAL_NEIGHBOUR_THRESHOLD :
            if src_index not in function_matches :
                if matchAttempt(src_index + 1, func_ea, file_match) :
                    return True
        return False

def matchFiles() :
    """Main loop responsible for the advancing the matching process"""
    global match_files, changed_functions, match_round_losers, call_hints_records, ext_unused_functions, once_seen_couples_src, once_seen_couples_bin

    # Don't forget all of the hints from the anchors
    for src_index, func_ea in anchor_hints :
        updateHints(src_index, func_ea)

    # Search for file hint strings, and try to locate more files based on them
    logger.info("Searching for file name \"hints\" to thicken the anchors list")
    # traverse all files, and tell them to try and match agents
    for match_file in match_files :
        match_file.attemptFindFileHints()
    # handle the match candidates
    roundMatchResults()

    # merge the results into the changed functions list
    for src_index, func_ea in match_round_losers :
        if src_index not in changed_functions :
            changed_functions[src_index] = set()
        changed_functions[src_index].add(bin_functions_ctx[func_ea])
    # reset the losers list
    match_round_losers = []

    # Search for useful "agents" to help the initial anchors list
    logger.info("Searching for \"agents\" to thicken the anchors list")
    # traverse all files, and tell them to try and match agents
    for match_file in match_files :
        match_file.attemptFindAgents()
    # handle the match candidates
    roundMatchResults()

    # merge the results into the changed functions list
    for src_index, func_ea in match_round_losers :
        if src_index not in changed_functions :
            changed_functions[src_index] = set()
        changed_functions[src_index].add(bin_functions_ctx[func_ea])
    # reset the losers list
    match_round_losers = []

    # print the state before the matching actually starts
    debugPrintState()

    logger.info("Start the main matching process")
    finished = False
    # while there is work to do
    while not finished :
        logger.info("Started a matching round")
        finished = True
        # First, Scan all of the (located) files
        for match_file in match_files :
            # tell the file to try and match itself
            match_file.attemptMatches()

        # Now, check out the changed functions first, and then the once seen functions
        for scoped_functions in [changed_functions, once_seen_couples_src] :
            for src_index in list(scoped_functions.keys()) :
                # check if already matched (already popeed out of the dict)
                if src_index in function_matches:
                    continue
                for bin_ctx in list(scoped_functions[src_index]) :
                    # check if already matched
                    if src_index not in scoped_functions :
                        continue
                    # check if relevant
                    if not src_functions_ctx[src_index].isValidCandidate(bin_ctx) :
                        scoped_functions[src_index].remove(bin_ctx)
                        continue
                    # check for a single call hint - this should be a sure match
                    if bin_ctx._call_hints is not None and len(bin_ctx._call_hints) == 1 :
                        declareMatch(list(bin_ctx._call_hints)[0]._src_index, bin_ctx._ea, REASON_SINGLE_CALL)
                        finished = False
                        continue
                    # check for a single xref hint - this should be a sure match
                    if len(set(bin_ctx._xref_hints)) == 1 :
                        declareMatch(bin_ctx._xref_hints[0]._src_index, bin_ctx._ea, REASON_SINGLE_XREF)
                        finished = False
                        continue
                    # simply compare them both
                    matchAttempt(src_index, bin_ctx._ea)
                    # add it to the once seen couples
                    if src_index not in once_seen_couples_src :
                        once_seen_couples_src[src_index] = set()
                    once_seen_couples_src[src_index].add(bin_ctx)
                    if bin_ctx._ea not in once_seen_couples_bin :
                        once_seen_couples_bin[bin_ctx._ea] = set()
                    once_seen_couples_bin[bin_ctx._ea].add(src_index)
                
                # if this is first loop, add all of the records from the matching seen couples
                if scoped_functions == changed_functions :
                    for match_record in match_round_candidates :
                        # source candidates
                        if match_record['src_index'] in once_seen_couples_src :
                            for bin_ctx in list(once_seen_couples_src[match_record['src_index']]) :
                                if src_functions_ctx[match_record['src_index']].isValidCandidate(bin_ctx) :
                                    matchAttempt(match_record['src_index'], bin_ctx._ea)
                                else :
                                    once_seen_couples_src[match_record['src_index']].remove(bin_ctx)                            
                        # binary candidates
                        if match_record['func_ea'] in once_seen_couples_bin :
                            for src_index in list(once_seen_couples_bin[match_record['func_ea']]) :
                                if src_functions_ctx[src_index].isValidCandidate(bin_functions_ctx[match_record['func_ea']]) :
                                    matchAttempt(src_index, match_record['func_ea'])
                                else :
                                    once_seen_couples_bin[match_record['func_ea']].remove(src_index)
                    # now reset the dict of changed functions
                    changed_functions = {}

                # check the round results now
                finished = (not roundMatchResults()) and finished

                # merge the results into the changed functions list
                for src_index, func_ea in match_round_losers :
                    bin_ctx = bin_functions_ctx[func_ea]
                    if src_index not in once_seen_couples_src :
                        once_seen_couples_src[src_index] = set()
                    once_seen_couples_src[src_index].add(bin_ctx)
                    if bin_ctx._ea not in once_seen_couples_bin :
                        once_seen_couples_bin[bin_ctx._ea] = set()
                    once_seen_couples_bin[bin_ctx._ea].add(src_index)
                # reset the losers list
                match_round_losers = []
            
            # if found a match, break the loop
            if not finished :
                break

        # If nothing has changed, check the a hint call order and hpoe for a sequential tie braker
        if finished :
            # check for disabled externals
            for ext_name in src_external_functions :
                ext_ctx = src_external_functions[ext_name]
                if not ext_ctx.used() :
                    ext_unused_functions.add(ext_name)
            new_call_hints_records = []
            # now match them
            for src_calls, bin_calls, src_parent, bin_parent, is_ext in call_hints_records :
                # start with a filter
                if is_ext :
                    src_calls = filter(lambda x : src_external_functions[x._name].active() and src_external_functions[x._name].used(), src_calls)
                    bin_calls = filter(lambda ea : ea not in bin_matched_ea, bin_calls)
                else :
                    src_calls = filter(lambda x : x.active() and x in src_parent._call_order, src_calls)
                    bin_calls = filter(lambda x : x.active() and x in bin_parent._call_order, bin_calls)
                if len(src_calls) > 0 and len(bin_calls) > 0 :
                    new_call_hints_records.append((src_calls, bin_calls, src_parent, bin_parent, is_ext))
                # now continue to the actual logic
                order_bins = {}
                order_srcs = {}
                # build the bin order
                for bin_ctx in bin_calls :
                    if bin_ctx not in bin_parent._call_order :
                        if not is_ext :
                            logger.warning("Found a probable Island inside function: 0x%x (%s)", bin_ctx._ea, bin_ctx._name)
                        continue
                    for call_path in bin_parent._call_order[bin_ctx] :
                        order_score = len(call_path.intersection(bin_calls))
                        if order_score not in order_bins :
                            order_bins[order_score] = set()
                        order_bins[order_score].add(bin_ctx)
                # build the src order
                for src_ctx in src_calls :
                    for call_path in src_parent._call_order[src_ctx] :
                        order_score = len(call_path.intersection(src_calls))
                        if order_score not in order_srcs :
                            order_srcs[order_score] = set()
                        order_srcs[order_score].add(src_ctx)
                # check that both orders match
                agreed_order_index = -1
                order_intersection = set(order_bins.keys()).intersection(set(order_srcs.keys()))
                if len(order_intersection) > 0 :
                    for order in xrange(max(order_intersection) + 1) :
                        if order not in order_srcs and order not in order_bins :
                            continue
                        if order not in order_srcs or order not in order_bins :
                            break
                        if len(order_bins[order]) != len(order_srcs[order]) :
                            break
                        agreed_order_index = order
                # now match each "bucket"
                order_list = list(order_bins.keys())
                order_list.sort()
                for order in order_list :
                    # stop when above the consensus level
                    if order > agreed_order_index :
                        break
                    bucket_srcs = order_srcs[order]
                    bucket_bins = order_bins[order]
                    # several candidates only work for normal functions
                    if is_ext and len(bucket_srcs) != 1 :
                        continue
                    # only update the hints, we can't have a single sure match
                    if len(bucket_srcs) != 1 :
                        for bin_ctx in bucket_bins :
                            bin_ctx.addHints(bucket_srcs, is_call = True)
                        continue
                    # match - had an exact sequential call order
                    src_candidate = bucket_srcs.pop()
                    bin_candidate = bucket_bins.pop()
                    if is_ext :
                        bin_matched_ea[bin_candidate] = src_candidate
                        src_candidate._ea = bin_candidate
                        logger.info("Matched external through sequential call hints: %s, 0x%x", src_candidate._name, src_candidate._ea)
                        finished = False
                        if src_candidate._hints is not None :
                            updated_ext_hints = filter(lambda ea : ea not in bin_matched_ea, src_candidate._hints)
                            for src_ext in src_calls :
                                src_ext.addHints(updated_ext_hints)
                                # Check for matches
                                matched_ea = src_ext.match()
                                if matched_ea is not None and matched_ea not in bin_matched_ea:
                                    bin_matched_ea[matched_ea] = src_external_functions[src_ext._name]
                                    src_ext._ea = matched_ea
                                    logger.info("Matched external function: %s == 0x%x (%s)", src_ext._name, matched_ea, sark.Function(matched_ea).name)
                    else :
                        # continue on only if the match is valid
                        if src_candidate.isValidCandidate(bin_candidate) :
                            declareMatch(src_candidate._src_index, bin_candidate._ea, REASON_CALL_ORDER)
                            finished = False
            # update the data-structure
            call_hints_records = new_call_hints_records

        # If nothing has changed, check for a function swallowing
        if finished :
            # find candidates at edges of gaps
            for match_file in match_files :
                # tell the file to try and search for swallows inside itself
                if match_file.attemptMatchSwallows() :
                    finished = False

        # We found some matches, pick the first one and continue again

    # check if we actually finished
    success_finish = len(filter(lambda x : x.active(), match_files)) == 0
    success_finish = success_finish and len(filter(lambda x : x.active(), src_external_functions)) == 0
    if not success_finish :
        # If matched nothing, debug and exit
        logger.warning("Completed a full scan without any improvement")
        debugPrintState()
    else:
        logger.info("Matched all library and external functions :)")

def debugPrintState(error = False) :
    """Prints a detailed debugging trace of the matching state of each source file, including overall statistics

    Args:
        error (bool, optional): True iff debug printting right before an error exit (False by default)
    """
    # How many functions we've matched?
    num_src_functions  = len(src_functions_list) - len(src_unused_functions)
    num_used_functions = num_src_functions - len(filter(lambda x : x.active() and (not x.used()), src_functions_ctx))
    num_ext_functions  = len(src_external_functions) - len(ext_unused_functions)
    logger.info("Matched Functions: %d/%d(/%d) (%d/%d)" % (len(function_matches), num_src_functions, num_used_functions, len(filter(lambda x : x.matched(), src_external_functions.values())), num_ext_functions))
    num_files = 0
    num_ref_files = 0
    located_files = 0
    filled_files  = 0
    filled_ref_files = 0
    for match_file in filter(lambda x : x._valid, match_files) :
        num_files += 1
        located_files += (1 if match_file.located() else 0)
        filled_files  += (1 if match_file.matched() else 0)
        reffed_file = False
        missed_ref_func = False
        for src_index in xrange(match_file._src_index_start, match_file._src_index_end + 1) :
            src_ctx = src_functions_ctx[src_index]
            if src_ctx.used() :
                reffed_file = True
                missed_ref_func = (src_index not in function_matches) or missed_ref_func
        num_ref_files    += (1 if reffed_file else 0)
        filled_ref_files += (1 if not missed_ref_func else 0)
    logger.info("File Statistics: Located %d/%d files, Finished %d/%d (%d/%d) files", located_files, num_files, filled_files, num_files, filled_ref_files, num_ref_files)
    logger.info("------------------------------------------------------------------------")
    printed_ghost = False
    # Source map, by files
    for match_file in filter(lambda x : x._valid, match_files) :
        logger.info("File: %s (%d %d %d %d)", match_file._name, match_file._remain_size, len(match_file._locked_eas), len(match_file._lower_locked_eas), len(match_file._upper_locked_eas))
        logger.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        logger.info("Src map:")
        for src_index in xrange(match_file._src_index_start, match_file._src_index_end + 1) :
            candidate_string = ', '.join(map(lambda x : "0x%x" % x._ea, src_functions_ctx[src_index]._followers))
            if src_index in src_anchor_list :
                logger.info("%03d: * (0x%x) - %s", src_index, function_matches[src_index], src_functions_ctx[src_index]._name)
            elif src_index in function_matches :
                logger.info("%03d: + (0x%x) - %s", src_index, function_matches[src_index], src_functions_ctx[src_index]._name)
            elif src_index in src_unused_functions :
                logger.info("%03d: - %s", src_index, src_functions_ctx[src_index]._name)
            elif not src_functions_ctx[src_index].used() :
                logger.info("%03d: _ - %s", src_index, src_functions_ctx[src_index]._name)
            elif src_functions_ctx[src_index]._is_static :
                logger.info("%03d: , - %s", src_index, src_functions_ctx[src_index]._name)
            else :
                logger.info("%03d: . [%s] - %s", src_index, candidate_string, src_functions_ctx[src_index]._name)
        logger.info("----------------------------------")
        # Bin map
        logger.info("Bin map")
        if not match_file.located() and printed_ghost :
            logger.info("File was not located, see previous such file")
            logger.info("==================================")  
            continue
        printed_ghost = printed_ghost or not match_file.located()
        # now actually print it
        for bin_ctx in (match_file._bin_functions_ctx if match_file.located() else floating_bin_functions) :
            bin_index = bin_ctx._bin_index
            bin_ea = bin_ctx._ea
            if bin_ctx._call_hints is not None :
                hints_options = ', '.join(map(lambda x : str(x._src_index), set(bin_ctx._call_hints)))
            else :
                hints_options = ''
            if bin_index in bin_anchor_list :
                logger.info("%03d: * (0x%x - %s) - (%s)", bin_index, bin_ea, bin_ctx._name, str(match_file.index(bin_ctx)))
            elif bin_ea in bin_matched_ea :
                logger.info("%03d: + (0x%x - %s) - (%s)", bin_index, bin_ea, bin_ctx._name, str(match_file.index(bin_ctx)))
            elif not bin_ctx.used() :
                logger.info("%03d: _ (0x%x - %s) [%s]", bin_index, bin_ea, bin_ctx._name, hints_options)
            elif not bin_ctx._is_static :
                logger.info("%03d: & (0x%x - %s)", bin_index, bin_ea, bin_ctx._name)
            else :
                logger.info("%03d: . (0x%x - %s) [%s]", bin_index, bin_ea, bin_ctx._name, hints_options)
        logger.info("==================================")    
    logger.info("External Functions:")
    for external_func in src_external_functions :
        ext_ctx = src_external_functions[external_func]
        if ext_ctx.matched() : 
            logger.info("+ %s - 0x%x (%s)", ext_ctx._name, ext_ctx._ea, sark.Function(ext_ctx._ea).name)
        elif external_func in ext_unused_functions :
            logger.info("- %s", ext_ctx._name)            
        else :
            logger.info(". %s", ext_ctx._name)
    # exit on error
    if error :
        criticalError()

def initMatchVars():
    """Prepares the global variables used for the matching for a new script execution"""
    global bin_functions_ctx, match_files, match_round_candidates, match_round_src_index, match_round_bin_ea, match_round_losers, src_unused_functions, ext_unused_functions, function_matches, bin_matched_ea, matching_reason, changed_functions, once_seen_couples_src, once_seen_couples_bin, call_hints_records, anchor_hints, str_file_hints, floating_bin_functions, floating_files, bin_suggested_names

    # same as the init list on the top of the file
    bin_functions_ctx       = {}        # bin ea => bin function ctx
    match_files             = []        # Orderred list of FileMatch instances, each for every source file

    match_round_candidates  = []        # valid match candidates (containing match records)
    match_round_src_index   = {}        # src index => match record
    match_round_bin_ea      = {}        # bin ea => match record
    match_round_losers      = []        # losers (to be tracked for changes) list for the match round (containing match records)

    src_unused_functions    = set()     # Set of (src) indices for unusd functions (disabled functions)
    ext_unused_functions    = set()     # Set of (src) names for unused external functions (all callers were disabled)

    function_matches        = {}        # Dictionary of all (non-external) matches: src index => bin ea
    bin_matched_ea          = {}        # Reverse dictionary for all matches: bin ea => src index / external ctx
    matching_reason         = {}        # Dictionary of all (non-external) matching reasons: src index => reason

    changed_functions       = {}        # Mappings for hints derived at the current matching round: src index => set of bin function ea
    once_seen_couples_src   = {}        # archive of all seen matching attempts. Mapping from src index => bin ctx
    once_seen_couples_bin   = {}        # archive of all seen matching attempts. Mapping from bin ea => src index
    call_hints_records      = []        # List of records describing the hints metadata, used as supplementary 

    anchor_hints            = []        # Temporary global holding the hints derived from the anchor matching
    str_file_hints          = set()     # global list of strings that hints about their source code file name

    floating_bin_functions  = None      # single global dictionary for the binary function contexts in the floating files
    floating_files          = []        # list of currently floating files

    bin_suggested_names     = {}        # Suggested Names for the matched and unmatched binary functions: ea => name

def criticalError():
    logger.error("Exitting the script")
    """Encounterred a critical error, and must stop the script"""
    exit(1)

def loadAndPrepareSource(files_config):
    """Loads the stored info on the source files, and prepares the source contexts for use

    Args:
        files_config (dict): the files configuration part of the overall JSON config
    """
    global src_file_names, src_external_functions, src_functions_list, src_functions_ctx, src_file_mappings, str_file_hints

    # Prepare & load the stats from each file (using the functions file)
    src_file_names = []
    logger.info("Loading the information regarding the compiled source files")
    logger.addIndent()
    for full_file_path in files_config :
        logger.debug("Parsing the canonical representation of file: %s", full_file_path.split(os.path.sep)[-1])
        src_file_names.append(full_file_path)
        parseFileStats(full_file_path, files_config[full_file_path])
    logger.removeIndent()

    # get the variables from the utils file
    src_functions_list, src_functions_ctx, src_file_mappings = getSourceFunctions()

    # Convert all function calls to contexts instead of names
    logger.info("Converting all function references to use the built contexts (instead of string names)")
    src_external_functions = {}
    for src_index, src_func_ctx in enumerate(src_functions_ctx) :
        # don't forget the file hint string
        str_file_hint = src_func_ctx.checkFileHint()
        if str_file_hint is not None :
            str_file_hints.add(str_file_hint)
        # split the functions to internal and external
        src_internal_calls = []
        src_external_calls = []
        src_func_ctx._src_index = src_index
        for call in src_func_ctx._calls :
            if call in src_functions_list :
                # should make sure to prioritize the call from the same file (duplicates are a nasty edge case)
                if src_functions_list.count(call) == 1 :
                    call_src_ctx = src_functions_ctx[src_functions_list.index(call)]
                else :
                    candidates = filter(lambda x : src_functions_ctx[x[0]]._file == src_func_ctx._file, filter(lambda x : x[1] == call, enumerate(src_functions_list)))
                    call_src_ctx = src_functions_ctx[candidates[0][0]]
                src_internal_calls.append(call_src_ctx)
            else :
                if call in libc.skip_function_names or len(call) == 0:
                    continue
                if call not in src_external_functions :
                    src_external_functions[call] = ExternalFunction(call)
                src_external_functions[call].addXref(src_func_ctx)
                src_external_calls.append(src_external_functions[call])
        src_func_ctx._calls = src_internal_calls
        src_func_ctx._externals = src_external_calls
        # the call order too
        new_order = {}
        for call in src_func_ctx._call_order :
            if call in libc.skip_function_names or len(call) == 0:
                continue
            if call in src_functions_list :
                key = src_functions_ctx[src_functions_list.index(call)]
            elif call in src_external_functions :
                key = src_external_functions[call]
            else : # a global data variable, skip it
                continue
            new_order[key] = []
            for path in src_func_ctx._call_order[call] :
                inner_calls = set()
                for inner_call in path :
                    if inner_call in libc.skip_function_names or len(inner_call) == 0:
                        continue
                    if inner_call in src_functions_list :
                        inner_calls.add(src_functions_ctx[src_functions_list.index(inner_call)])
                    elif inner_call in src_external_functions :
                        inner_calls.add(src_external_functions[inner_call])
                    else :
                        continue
                new_order[key].append(inner_calls)
        src_func_ctx._call_order = new_order

    # Build up an xref map too
    for src_func_ctx in src_functions_ctx :
        for call in src_func_ctx._calls :
            call._xrefs.add(src_func_ctx)

def loadAndMatchAnchors(anchors_config):
    """Loads the list of anchor functions, and try to match them with the binary

    Args:
        anchors_config (list): list of anchor src indices as extracted from the JSON config
    """
    global src_anchor_list, bin_anchor_list, matched_anchors_ea, src_file_names, src_file_mappings
    # Parse the anchors file
    logger.info("Loading the list of Anchor functions")
    src_anchor_list = anchors_config

    # Locate the anchor functions
    logger.info("Searching for the Anchor functions in the binary")
    logger.addIndent()
    all_bin_functions = list(idautils.Functions())
    # range narrowing variables
    lower_match_ea = None
    upper_match_ea = None
    lower_match_index = None
    upper_match_index = None
    lower_border_ea = 0
    upper_border_ea = idc.BADADDR
    lower_border_index = None
    upper_border_index = None
    function_range = None
    overall_num_functions = len(src_functions_list)
    multiple_option_candidates = []
    matched_anchors_ea = {}
    anchor_eas = []
    first_const_anchor = True
    efficient_const_search = False
    # pre-scan (for optimization reasons)
    anchor_stats = []
    num_const_clues  = 0
    all_const_clues  = set()
    all_string_clues = set()
    for src_anchor_index in list(src_anchor_list) :
        src_func_ctx = src_functions_ctx[src_anchor_index]
        is_str, threshold, anchor_clues = isAnchor(src_func_ctx, logger)
        # sanity check
        if anchor_clues is None :
            src_anchor_list.remove(src_anchor_index)
            logger.warning("Anchor candidate %s (%d) failed as an anchor function", src_func_ctx._name, src_anchor_index)
            continue
        anchor_stats.append((src_anchor_index, src_func_ctx, is_str, threshold, anchor_clues))
        if is_str :
            all_string_clues = all_string_clues.union(anchor_clues)
        else :
            num_const_clues += len(anchor_clues)
            all_const_clues = all_const_clues.union(anchor_clues)

    # Traverse all of the strings only once, it is heavy
    anchor_bin_strs = {}
    # Scanning the entire string list and checking against each anchor string - O(kN) - efficient in memory
    if len(all_string_clues) > 0 :
        for bin_str_ctx in idaStringList() :
            bin_str = str(bin_str_ctx)
            if bin_str in all_string_clues :
                if bin_str not in anchor_bin_strs :
                    anchor_bin_strs[bin_str] = []
                anchor_bin_strs[bin_str].append(bin_str_ctx)
  
    # full scan (maybe only string scan)
    for src_anchor_index, src_func_ctx, is_str, threshold, anchor_clues in anchor_stats :
        candidates = None
        candidate_sets = []
        # scan the full clue list
        for clue_idx, clue in enumerate(anchor_clues) :
            # strings
            if is_str :
                current_set = set()
                # found the string clue in the binary
                if clue in anchor_bin_strs :
                    for bin_str in anchor_bin_strs[clue] :
                        for ref in idautils.DataRefsTo(bin_str.ea) :
                            caller_func = idaapi.get_func(ref)
                            if caller_func is None :
                                continue
                            if lower_border_ea <= caller_func.start_ea and caller_func.start_ea <= upper_border_ea :
                                current_set.add(caller_func.start_ea)
            # consts
            else :
                # measure some times (for the first one only)
                if first_const_anchor :
                    start_time = time.time()
                # scanning the entire firmware per anchor const - O(kN)
                current_set = set()
                # search for it in the binary (non efficient)
                if lower_match_index is None or not efficient_const_search :
                    search_pos = lower_border_ea if not first_const_anchor else 0
                    while first_const_anchor or search_pos < upper_border_ea :
                        match_ea, garbage = idc.FindImmediate(search_pos, idc.SEARCH_DOWN, clue)
                        search_pos = match_ea + 1
                        # Filter out mismatches
                        if match_ea == idc.BADADDR :
                            break
                        # Filter out matches that are not inside functions
                        caller_func = idaapi.get_func(match_ea)
                        if caller_func is not None :
                            current_set.add(caller_func.start_ea)
                    # measure the end time too
                    if first_const_anchor :
                        end_time = time.time()
                        overall_search_time = (end_time - start_time) * num_const_clues
                        if lower_match_index is None :
                            efficient_const_search = MAXIMAL_CONST_SEARCH_TIME <= overall_search_time
                        else :
                            efficient_const_search = MAXIMAL_CONST_SEARCH_RATE <= overall_search_time * 1.0 / (upper_match_index - lower_match_index + 1)
                        # no longer the first const
                        first_const_anchor = False
                # efficient search
                else :
                    if function_range is None :
                        logger.info("Anchor search - switching to efficient const search mode")
                        # build the fast mapping, and then continue as before
                        function_range = []
                        for function_ea in all_bin_functions[lower_border_index : upper_border_index] :
                            function_range.append((function_ea, locateAnchorConsts(function_ea, all_const_clues)))  
                    # Now actually search for the wanted const value in the result sets
                    for function_ea, const_set in function_range :
                        if clue in const_set :
                            current_set.add(function_ea)

            # Same merging logic, for strings and consts
            # simply add this option (only if rellevant)
            if len(current_set) > 0 :
                candidate_sets.append(current_set)
            # check if reached the limit
            if len(candidate_sets) >= threshold :
                # start checking for a match
                candidate_attempt = {}
                for candidate_set in candidate_sets :
                    for candidate in candidate_set :
                        if candidate not in candidate_attempt :
                            candidate_attempt[candidate] = 0
                        candidate_attempt[candidate] += 1
                candidates = filter(lambda x : candidate_attempt[x] >= threshold, candidate_attempt.keys())
                future_candidates = filter(lambda x : candidate_attempt[x] >= threshold - (len(anchor_clues) - (clue_idx + 1)), candidate_attempt.keys())
                # stop condition
                if len(candidates) == 1 and len(future_candidates) == 0 :
                    break

        # check if needs to decide between multiple options
        if candidates is not None and len(candidates) > 1 :
            sorted_candidates = candidate_attempt.keys()
            sorted_candidates.sort(key = lambda x : candidate_attempt[x], reverse = True)
            # if we have an absolute winner, than pick it (safe to access both cells because len() > 1)
            if candidate_attempt[sorted_candidates[0]] > candidate_attempt[sorted_candidates[1]] :
                candidates = [sorted_candidates[0]]
                    
        # check if we have any candidate left
        if candidates is None or len(candidates) == 0 :
            logger.warning("Anchor function - %s: Failed to find a match", src_functions_list[src_anchor_index])
            src_anchor_list.remove(src_anchor_index)
        elif len(candidates) == 1 :
            caller_func = sark.Function(candidates.pop())
            logger.info("Anchor function - %s: Matched at 0x%x (%s)", src_functions_list[src_anchor_index], caller_func.startEA, caller_func.name)
            matched_anchors_ea[src_anchor_index] = caller_func.startEA
            anchor_eas.append(caller_func.startEA)
            declareMatch(src_anchor_index, caller_func.startEA, REASON_ANCHOR)
            # use the match to improve our search range
            # first anchor
            if len(matched_anchors_ea.keys()) == 1 :
                lower_match_ea = caller_func.startEA
                upper_match_ea = lower_match_ea
                lower_match_index = all_bin_functions.index(caller_func.startEA)
                upper_match_index = lower_match_index
                change = True
            else :
                # try to improve the lower border
                if caller_func.startEA < lower_match_ea :
                    lower_match_ea = caller_func.startEA
                    new_lower_index = all_bin_functions.index(caller_func.startEA)
                    if function_range is not None :
                        function_range = function_range[new_lower_index - lower_match_index : ]
                    lower_match_index = new_lower_index
                    change = True
                # try to improve the lower border
                elif upper_match_ea < caller_func.startEA :
                    upper_match_ea = caller_func.startEA
                    new_upper_index = all_bin_functions.index(caller_func.startEA)
                    if function_range is not None :
                        function_range = function_range[ : new_upper_index - upper_match_index]
                    upper_match_index = new_upper_index
                    change = True
                else :
                    change = False
            # adjust the borders accordingly
            if change :
                locked_gap = upper_match_index - lower_match_index + 1
                lower_border_index = lower_match_index - (overall_num_functions - locked_gap)
                upper_border_index = upper_match_index + (overall_num_functions - locked_gap)
                lower_border_ea = all_bin_functions[lower_match_index - (overall_num_functions - locked_gap)]
                upper_border_ea = all_bin_functions[upper_match_index + (overall_num_functions - locked_gap)]
        else :
            logger.warning("Anchor function - %s: Found several matches (%d), will check it again later", src_functions_list[src_anchor_index], len(candidates))
            multiple_option_candidates.append((src_anchor_index, candidates))
    logger.removeIndent()

    # double check the candidates which had multiple options (if narrowed the search space)
    if lower_match_ea is not None :
        for src_anchor_index, candidates in multiple_option_candidates :
            filterred_candidates = filter(lambda x : lower_match_ea <= x and x <= upper_match_ea, candidates)
            # matched
            if len(filterred_candidates) == 1 :
                caller_func = sark.Function(filterred_candidates.pop())
                logger.info("Anchor function (revived) - %s: Matched at 0x%x (%s)", src_functions_list[src_anchor_index], caller_func.startEA, caller_func.name)
                matched_anchors_ea[src_anchor_index] = caller_func.startEA
                anchor_eas.append(caller_func.startEA)
                declareMatch(src_anchor_index, caller_func.startEA, REASON_ANCHOR)
            # still not found
            else :
                src_anchor_list.remove(src_anchor_index)

    # make sure we found atleast one anchor function
    if len(src_anchor_list) == 0 :
        logger.error("Failed to match even a single Anchor function")
        criticalError()

    # Create a binary anchor list for future use
    bin_anchor_list = []
    for src_anchor_index in src_anchor_list :
        bin_anchor_list.append(all_bin_functions.index(function_matches[src_anchor_index]))

    # Sort the file list according to the (bin) order of the anchors    
    old_anchor_list = list(src_anchor_list)
    src_anchor_list.sort(key = lambda x : bin_anchor_list[old_anchor_list.index(x)])

    # Sanity Check: make sure that the files are not mixed up
    anchor_files = []
    started = True
    for src_anchor_index in src_anchor_list :
        if not started and src_functions_ctx[src_anchor_index]._file != anchor_files[-1] :
            if src_functions_ctx[src_anchor_index]._file in anchor_files :
                logger.error("Sanity check failed: the matched anchor functions are tangled between files...")
                criticalError()
        if src_functions_ctx[src_anchor_index]._file not in anchor_files :
            anchor_files.append(src_functions_ctx[src_anchor_index]._file)
        started = False

    # remove empty files (wierd edge case)
    src_file_names = filter(lambda x : len(src_file_mappings[x]) != 0, src_file_mappings.keys())
    removed_names  = filter(lambda x : len(src_file_mappings[x]) == 0, src_file_mappings.keys())
    for name in removed_names :
        src_file_mappings.pop(name)

    # Now sort the src file names list according to the sorted anchors
    src_file_names = anchor_files + list(set(src_file_names).difference(anchor_files))

def locateFileBoundaries():
    """Uses the anchors to create initial file borders in the binary address space"""
    global bin_functions_ctx, match_files, floating_bin_functions, floating_files

    logger.info("Zooming-in to define the tentative borders for each source file in the binary address space")
    # Split the matched anchor functions to their respective files
    file_to_anchor_mapping = {}
    for path in src_file_names :
        file_to_anchor_mapping[path] = []
        for src_ctx in src_file_mappings[path] :
            if src_ctx._src_index in matched_anchors_ea :
                file_to_anchor_mapping[path].append(src_ctx)

    # construct the list of minimal bound and maximal bound for each file
    # this could be tricky since not all of our files are going to have anchor functions - including the first and the last file
    all_bin_functions = list(idautils.Functions())
    file_min_bound = []
    file_max_bound = []
    file_lower_gap = []
    file_upper_gap = []
    first_anchor_index = None
    last_anchor_index  = None
    # 1st round, basic estimates using only the anchors (files without anchors are placed artificialy at the end)
    for file_index, file_name in enumerate(src_file_names) :
        # return back to this file after the initial round
        if len(file_to_anchor_mapping[file_name]) == 0 :
            break
        if first_anchor_index is None :
            first_anchor_index = file_index
        last_anchor_index = file_index
        # else, we have an anchor, and we can have basic bounds for now
        min_anchor = min(map(lambda x : matched_anchors_ea[x._src_index], file_to_anchor_mapping[file_name]))
        max_anchor = max(map(lambda x : matched_anchors_ea[x._src_index], file_to_anchor_mapping[file_name]))
        min_anchor_bin_index = all_bin_functions.index(min_anchor)
        max_anchor_bin_index = all_bin_functions.index(max_anchor)
        base_leftover_size = len(src_file_mappings[file_name]) - (max_anchor_bin_index - min_anchor_bin_index + 1)
        file_min_bound.append(min_anchor_bin_index - base_leftover_size)
        file_max_bound.append(max_anchor_bin_index + base_leftover_size)
        file_lower_gap.append(base_leftover_size)
        file_upper_gap.append(base_leftover_size)
    # create rough lower bounds to all files
    additional_lower_bounds = []
    prev_hard_limit = -1
    for file_index in xrange(first_anchor_index, last_anchor_index + 1) :
        additional_lower_bounds = additional_lower_bounds + [prev_hard_limit]
        prev_hard_limit = file_max_bound[file_index] - file_upper_gap[file_index] + 1
    # create the same kind of upper bounds to all files, going from top to buttom
    additional_upper_bounds = []
    prev_hard_limit = len(all_bin_functions)
    for file_index in xrange(last_anchor_index, first_anchor_index - 1, -1) :
        additional_upper_bounds = [prev_hard_limit] + additional_upper_bounds
        prev_hard_limit = file_min_bound[file_index] + file_lower_gap[file_index] - 1
    # Now preform the full scan again, with all of the information we gathered in previous phases
    for file_index in xrange(first_anchor_index, last_anchor_index + 1) :
        next_checks = file_index + 1 < last_anchor_index + 1
        # if we reached the anchor above us, we need to shrink
        if next_checks and file_max_bound[file_index] >= file_min_bound[file_index + 1] + file_lower_gap[file_index + 1] :
            new_upper_limit = file_min_bound[file_index + 1] + file_lower_gap[file_index + 1] - 1
            new_upper_gap  = file_upper_gap[file_index] - (new_upper_limit - file_max_bound[file_index])
            file_max_bound = file_max_bound[:file_index] + [new_upper_limit] + file_max_bound[file_index + 1:]
            file_upper_gap = file_upper_gap[:file_index] + [new_upper_gap] + file_upper_gap[file_index + 1:]
        # if the file above us is reaching our top anchor, he needs to shrink too
        if next_checks and file_max_bound[file_index] - file_upper_gap[file_index] >= file_min_bound[file_index + 1] :
            new_lower_limit = file_max_bound[file_index] - file_upper_gap[file_index] + 1
            new_lower_gap   = file_lower_gap[file_index + 1] - (new_lower_limit - file_min_bound[file_index + 1])
            file_min_bound = file_min_bound[:file_index + 1] + [new_lower_limit] + file_min_bound[file_index + 2:]
            file_lower_gap = file_lower_gap[:file_index + 1] + [new_lower_gap] + file_lower_gap[file_index + 2:]
        # if we are reaching too low, we should shrink
        if file_min_bound[file_index] < additional_lower_bounds[file_index] :
            new_lower_limit = additional_lower_bounds[file_index]
            new_lower_gap  = file_lower_gap[file_index] - (new_lower_limit - file_min_bound[file_index])
            file_min_bound = file_min_bound[:file_index] + [new_lower_limit] + file_min_bound[file_index + 1:]
            file_lower_gap = file_lower_gap[:file_index] + [new_lower_gap] + file_lower_gap[file_index + 1:]
        # if we are reaching too high, we should shrink
        if file_max_bound[file_index] > additional_upper_bounds[file_index] :
            new_upper_limit = additional_upper_bounds[file_index]
            new_upper_gap  = file_upper_gap[file_index] - (new_upper_limit - file_max_bound[file_index])
            file_max_bound = file_max_bound[:file_index] + [new_upper_limit] + file_max_bound[file_index + 1:]
            file_upper_gap = file_upper_gap[:file_index] + [new_upper_gap] + file_upper_gap[file_index + 1:]

    # Set up the scoped binary functions
    overall_num_functions = len(src_functions_list)
    num_locked_functions = max(bin_anchor_list) - min(bin_anchor_list) + 1
    bin_start_index = file_min_bound[0] - (overall_num_functions - num_locked_functions)
    bin_end_index   = file_max_bound[-1] + (overall_num_functions - num_locked_functions)
    logger.info("Analyzing all of the binary functions in the chosen scope")
    # prepare all of the functions
    for bin_index, func_ea in enumerate(all_bin_functions[bin_start_index : bin_end_index + 1]) :
        bin_functions_ctx[func_ea] = analyzeFunction(func_ea, False)
        bin_functions_ctx[func_ea]._bin_index = bin_start_index + bin_index
        bin_functions_ctx[func_ea].rankConsts()

    # Can now slice it up and build the FileMatch structure
    for file_index, file_name in enumerate(src_file_names) :
        # source indices
        src_start_index = src_file_mappings[file_name][0]._src_index
        src_end_index   = src_file_mappings[file_name][-1]._src_index
        # check if this file wasn't located yet
        if len(file_to_anchor_mapping[file_name]) == 0 :
            # a "floating" file that will hold the entire binary functions as possible candidates
            if floating_bin_functions is None :
                floating_bin_functions = map(lambda ea : bin_functions_ctx[ea], all_bin_functions[bin_start_index : bin_end_index + 1])
            file_match = FileMatch(file_name, src_start_index, src_end_index, None, bin_start_index, bin_end_index, overall_num_functions - num_locked_functions)
            floating_files.append(file_match)
        else:
            # binary indices
            local_bin_start_index = file_min_bound[file_index]
            local_bin_end_index   = file_max_bound[file_index]
            # scoped binary functions
            local_bins_ctx = map(lambda ea : bin_functions_ctx[ea], all_bin_functions[local_bin_start_index : local_bin_end_index + 1])
            file_match = FileMatch(file_name, src_start_index, src_end_index, local_bins_ctx, local_bin_start_index, local_bin_end_index, src_end_index - src_start_index + 1)
        # add this file instance to the list
        match_files.append(file_match)
        # connect the source functions to the file too
        for src_ctx in src_file_mappings[file_name] :
            src_ctx._file = match_files[file_index]

def prepareBinFunctions():
    """Prepares all of the binary contexts for use"""
    global bin_external_functions
    
    logger.info("Converting all binary function references to use the built contexts (instead of eas)")
    # Traverse all of the contexts of the binary functions, and split them to internal / external calls
    bin_external_functions = set()
    for bin_func_ctx in bin_functions_ctx.values() :
        bin_internal_calls = []
        bin_external_calls = []
        for call_ea in bin_func_ctx._calls :
            if call_ea in bin_functions_ctx.keys() :
                bin_internal_calls.append(bin_functions_ctx[call_ea])
            else :
                bin_external_calls.append(call_ea)
        bin_func_ctx._calls = bin_internal_calls
        bin_func_ctx._externals = bin_external_calls
        bin_external_functions.update(bin_external_calls)
        # the call order too
        new_order = {}
        for call_ea in bin_func_ctx._call_order :
            if call_ea in bin_functions_ctx.keys() :
                key = bin_functions_ctx[call_ea]
            else :
                key = call_ea
            new_order[key] = []
            for path in bin_func_ctx._call_order[call_ea] :
                inner_calls = set()
                for inner_call in path :
                    if inner_call in bin_functions_ctx.keys() :
                        inner_calls.add(bin_functions_ctx[inner_call])
                    else :
                        inner_calls.add(inner_call)
                new_order[key].append(inner_calls)
        bin_func_ctx._call_order = new_order

    # Build up an xref map too
    for bin_func_ctx in bin_functions_ctx.values() :
        for call in bin_func_ctx._calls :
            call._xrefs.add(bin_func_ctx)

    # Now check for outer xrefs
    for bin_func_ctx in bin_functions_ctx.values() :
        outer_ref = False
        for ref in filter(lambda x : idaapi.get_func(x) is not None, sark.Line(bin_func_ctx._ea).crefs_to) :
            if sark.Function(ref).startEA not in bin_functions_ctx :
                outer_ref = True
                break
        if not outer_ref :
            bin_func_ctx.markStatic()

def generateSuggestedNames():
    """Generates the suggested names for the binary functions"""
    global bin_suggested_names

    # We have several goals:
    # 0. Clean naming convention - includes the library's name
    # 1. Avoid collisions - same name in different filse
    # 2. Best effort #1 - use file name if known, and function name isn't
    # 3. Best effort #2 - use lib name if a locked function

    rename_file = lambda x : '.'.join(x.split('.')[:-1]).replace(os.path.sep, '_')
    logger.info("Generating the suggested names for the located functions")

    # 1. check which (matched) functions share the same name
    matched_src_ctxs = filter(lambda x : x.matched(), src_functions_ctx)
    all_match_name = map(lambda x : x._name, matched_src_ctxs)
    duplicate_match_names = filter(lambda x : all_match_name.count(x) > 1, all_match_name)
    # 2. Now rename them if necessary
    for src_ctx in filter(lambda x : x._name in duplicate_match_names, matched_src_ctxs):
        src_ctx._name = rename_file(src_ctx._file._name) + '_' + src_ctx._name

    # 3. Scan all of the files, and name their functions
    for match_file in filter(lambda x : x.valid() and x.located(), match_files) :
        file_name = rename_file(match_file._name)
        for bin_ctx in match_file._bin_functions_ctx :
            # 1. Matched
            if bin_ctx.matched():
                bin_suggested_names[bin_ctx._ea] = library_name + '_' + bin_ctx.match()._name
            # 2. Single file
            elif len(bin_ctx._files) == 1 :
                bin_suggested_names[bin_ctx._ea] = library_name + '_' + file_name + '_' + ('%X' % (bin_ctx._ea))
            # 3. Library related
            else:
                bin_suggested_names[bin_ctx._ea] = library_name + '_' + ('%X' % (bin_ctx._ea))

def renameChosenFunctions(bin_ctxs):
    """Renames the chosed set ot binary functions

    Args:
        bin_cts (list): list of binary contexts for the renamed (located) functions
    """
    for bin_ctx in bin_ctxs:
        # sanity check
        if bin_ctx._ea not in bin_suggested_names:
            logger.warning("Failed to rename function at 0x%x, has no name for it", bin_ctx._ea)
            continue
        # rename it
        renameIDAFunction(bin_ctx._ea, bin_suggested_names[bin_ctx._ea])

def startMatch(config_path, lib_name, used_logger):
    """Starts matching the wanted source library to the loaded binary

    Args:
        config_path (str): path to the config file of the source library
        lib_name (str): name of the matched open source library
        used_logger (logger): logger instance to be used (init for us already)
    """
    global logger, library_name

    logger = used_logger
    library_name = lib_name

    # always init the utils before we start
    initUtils()

    # Init our variables too
    initMatchVars()

    # Load the configuration file
    fd = open(config_path, 'r')
    config_dict = json.load(fd, object_pairs_hook=collections.OrderedDict)
    fd.close()

    # Load the source functions, and prepare them for use
    loadAndPrepareSource(config_dict['Files'])

    # Load and match the anchor functions
    loadAndMatchAnchors(config_dict['Anchors (Src Index)'])

    # Locate the file boundaries in the binary functions list
    locateFileBoundaries()

    # Prepare the located binary functions for first use
    prepareBinFunctions()

    # Now try to match all of the files
    matchFiles()

    # Generate the suggested function names
    generateSuggestedNames()

    # Show the GUI window with the matches

    # Stub:
    # renameChosenFunctions(filter(lambda x : x._ea in bin_suggested_names, bin_functions_ctx.values()))
