######################
## Custom Exception ##
######################

class AssumptionException(Exception):
    """Exception that represents a broken inner assumption."""

    pass

######################
## Matching Classes ##
######################

class MatchSequence(object):
    """A class representing a (geographic) sequence of matched binary functions.

    Attributes
    ----------
        bin_lower_ctx (FunctionContext): the lowest matched binary function in the sequence
        bin_upper_ctx (FunctionContext): the highest matched binary function in the sequence

    Notes
    -----
        We can NOT save indices (bin_index), since the file's bin functions list is dynamic.
        Therefor, we save full contexts, and search their index in the list each time we need it.
    """

    def __init__(self, bin_ctx):
        """Create a match sequence that contains a single (matched) binary function.

        Args:
            bin_ctx (FunctionContext): the first context in our match sequence
        """
        self.bin_lower_ctx = bin_ctx
        self.bin_upper_ctx = bin_ctx

    def enlarge(self, bin_ctx, is_lower):
        """Add a new matched binary context to the top/bottom of the current sequence.

        Args:
            bin_ctx (FunctionContext): newly added binary context
            is_lower (bool): True iff should be inserted at the lower end
        """
        if is_lower:
            self.bin_lower_ctx = bin_ctx
        else:
            self.bin_upper_ctx = bin_ctx

    def merge(self, sequence, is_lower):
        """Merge a sequence into our own sequence (thus killing the supplied sequence).

        Args:
            sequence (MatchSequence): merged match sequence instance
            is_lower (bool): True iff should be inserted at the lower end
        """
        if is_lower:
            self.bin_lower_ctx = sequence.bin_lower_ctx
        else:
            self.bin_upper_ctx = sequence.bin_upper_ctx

class FileMatch(object):
    """A class representing a match attempt of a full source file.

    Attributes
    ----------
        name (str): name of the file (from the list of compiled files)
        located (bool): True iff already located at least one function in the file (otherwise we till don't know where it is)
        valid (bool): True iff the file play a role in the matching process (False means it was probably ifdeffed out)
        _src_index_start (int): source index of the first function in the source file
        _src_index_end (int): source index of last function in the source file
        _bin_functions_ctx (list): list of all candidate binary functions for this file (containing FunctionContext instances)
        _bin_limit_lower (int): binary index (in all of the functions) of the lowest binary candidate for this file
        _bin_limit_upper (int): binary index (in all of the functions) of the highest binary candidate for this file
        _lower_leftovers (int): size (in functions) of the lower "safety" gap (from a last valid match to the start of the file)
        _upper_leftovers (int): size (in functions) of the upper "safety" gap (from a last valid match to the end of the file)
        _match_sequences (list): Ordered list of match sequences in the file (containing MatchSequence instances)
        _disabled (int): number of disabled (linker optimized) functions that were found before we located our file
        _remain_size (int): number of source functions that are still to be matched
        _lower_match_ctx (FunctionContext): the lowest function that was matched till now
        _upper_match_ctx (FunctionContext): the highest function that was matched till now
        _locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when the FileMatch instance was created
        _lower_locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when expanding the match sequences downward
        _upper_locked_eas (set): set of (unmatched) eas that were "locked" between two binary matches when expanding the match sequences upward
        _engine (MatchEngine): match engine context with the scope for the matching process
    """

    def __init__(self, name, src_index_start, src_index_end, fuzzy_bin_functions_ctx, bin_limit_lower, bin_limit_upper, src_scope, engine):
        """Create a FileMatch instance according to initial binary bounds and initial anchors matched.

        Args:
            name (str): name of the file (from the list of compiled files)
            src_index_start (int): source index of the first function in the source file
            src_index_end (int): source index of last function in the source file
            fuzzy_bin_functions_ctx (list): initial list of all candidate binary functions for this file (containing FunctionContext instances)
            bin_limit_lower (int): binary index (in all of the functions) of the lowest binary candidate for this file
            bin_limit_upper (int): binary index (in all of the functions) of the highest binary candidate for this file
            src_scope (int): number of src functions that are currently in scope of this file (differs between located and unlocated files)
            engine (MatchEngine): match engine context with the scope for the matching process
        """
        self.name                = name
        self.located             = src_scope == (src_index_end - src_index_start + 1)
        self.valid               = True
        self._engine             = engine
        self._src_index_start    = src_index_start
        self._src_index_end      = src_index_end
        self._bin_functions_ctx  = fuzzy_bin_functions_ctx
        self._bin_limit_lower    = bin_limit_lower
        self._bin_limit_upper    = bin_limit_upper
        self._lower_leftovers    = None
        self._upper_leftovers    = None
        # ordered list of matching sequences
        self._match_sequences    = []
        self._disabled           = 0

        # calculate the remaining size
        if self.located:
            inner_matches_indices = set(self._engine.matchedSrcIndices()).intersection(range(self._src_index_start, self._src_index_end + 1))
            self._remain_size = self._src_index_end - self._src_index_start + 1
            self._remain_size -= len(inner_matches_indices)
        else:
            self._remain_size = src_scope
        # find the match boundaries
        self._lower_match_ctx = None
        self._upper_match_ctx = None

        # take ownership over the contained functions
        for bin_index, bin_ctx in enumerate(self._bin_functions_ctx if self.located else self._engine.floatingBinFunctions()):
            bin_ctx.linkFile(self)
            # can't use "matched()" because we are in a pre-updateHints() phase
            if self._engine.binMatched(bin_ctx.ea):
                if self._lower_match_ctx is None:
                    self._lower_match_ctx = bin_ctx
                self._upper_match_ctx = bin_ctx
                if self.located:
                    self.cleanupMatches(bin_ctx)

        # take full ownership of functions between the two match indices (if they are indeed mine)
        self._locked_eas = set()
        self._lower_locked_eas = set()
        self._upper_locked_eas = set()
        if self.located:
            bin_range = range(self._bin_functions_ctx.index(self._lower_match_ctx), self._bin_functions_ctx.index(self._upper_match_ctx) + 1)
            self._locked_eas.update(set(map(lambda x: self._bin_functions_ctx[x].ea, bin_range)))
            for bin_index in bin_range:
                bin_ctx = self._bin_functions_ctx[bin_index]
                bin_ctx.linkFile(self)
                # can't use "matched()" because we are in a pre-updateHints() phase
                if self._engine.binMatched(bin_ctx.ea):
                    self._locked_eas.remove(bin_ctx.ea)

        # set up the leftovers using the matched index (if we have such)
        if self._lower_match_ctx is not None:
            self._lower_leftovers = self._lower_match_ctx.index - self._bin_limit_lower
            self._upper_leftovers = self._bin_limit_upper - self._upper_match_ctx.index

    def matched(self):
        """Check if the entire file was matched.

        Return Value:
            True iff the entire file was matched
        """
        return self._remain_size == 0

    def active(self):
        """Check if the given file is still active and waiting to be matched.

        Return Value:
            return True iff the file is valid() and wasn't matched() yet
        """
        return self.valid and not self.matched()

    def index(self, bin_ctx):
        """Find the index of the function's match sequence.

        Assumptions:
            bin_ctx is contained in the file's list of binary functions

        Args:
            bin_ctx (FunctionContext): binary context of the function search for

        Return Value:
            Index of the function's match sequence (or None if failed)
        """
        if self.located:
            bin_index = self._bin_functions_ctx.index(bin_ctx)
            for seq_index, cur_seq in enumerate(self._match_sequences):
                try:
                    if self._bin_functions_ctx.index(cur_seq.bin_lower_ctx) <= bin_index and bin_index <= self._bin_functions_ctx.index(cur_seq.bin_upper_ctx):
                        return seq_index
                except ValueError:
                    # A False positive broke our invariants
                    return None
        return None

    def contains(self, bin_ctx):
        """Check if the given binary function is contained in the scope of the (located) file.

        Args:
            bin_ctx (FunctionContext): binary function to be searched

        Return value:
            True iff the bin_ctx is located in the scope of the file
        """
        return self.located and bin_ctx in self._bin_functions_ctx

    def cleanupMatches(self, bin_ctx):
        """Clean the list of match sequences, merging adjacent sequences if needed.

        Args:
            bin_ctx (FunctionContext): newly added match
        """
        # the empty case
        if len(self._match_sequences) == 0:
            self._match_sequences.append(MatchSequence(bin_ctx))
            return
        # the interesting case
        match_index = self._bin_functions_ctx.index(bin_ctx)
        # Now scan the entire list
        for seq_index, current_seq in enumerate(self._match_sequences):
            current_seq_lower_index = self._bin_functions_ctx.index(current_seq.bin_lower_ctx)
            current_seq_upper_index = self._bin_functions_ctx.index(current_seq.bin_upper_ctx)
            # insert way before
            if match_index + 1 < current_seq_lower_index:
                self._match_sequences = self._match_sequences[:seq_index] + [MatchSequence(bin_ctx)] + self._match_sequences[seq_index:]
                return
            # merge before
            elif match_index + 1 == current_seq_lower_index:
                current_seq.enlarge(bin_ctx, is_lower=True)
                return
            # merge after
            elif match_index - 1 == current_seq_upper_index:
                current_seq.enlarge(bin_ctx, is_lower=False)
                # check if we merged with the next one
                if seq_index + 1 < len(self._match_sequences):
                    next_seq = self._match_sequences[seq_index + 1]
                    if match_index + 1 == self._bin_functions_ctx.index(next_seq.bin_lower_ctx):
                        current_seq.merge(next_seq, is_lower=False)
                        self._match_sequences.remove(next_seq)
                # finished
                return
            # sanity check
            if current_seq_lower_index <= match_index and match_index <= current_seq_upper_index:
                self._engine.logger.error("Sanity check failed in cleanupMatches(): matched a function twice in file %s", self.name)
                raise AssumptionException()
            # continue to the next case
        # if we still have a new sequence, it means it is way after the last one
        self._match_sequences.append(MatchSequence(bin_ctx))

    def disableSources(self, removed_sources):
        """Update the file that several source functions where ifdeffed out / inlined.

        Note:
            Can happen only in two cases:
            1. Finished matching all of the binary functions in our file, the remaining sources will be disabled
            2. A floating file responds to the fact that case #1 just happened

        Args:
            removed_sources (collection): collection of source indices for the removed functions
        """
        # case #1
        if self.located:
            self._engine.markUnused(removed_sources)
            self._remain_size = 0
        # case #2
        else:
            num_removed = len(removed_sources)
            floating_representative = self._engine.floatingRepresentative()
            lower_part = max(removed_sources) < floating_representative._lower_match_ctx.index
            upper_part = floating_representative._upper_match_ctx.index < min(removed_sources)
            # adjust our margins
            if upper_part:
                self._remain_size -= num_removed
                # shrink the global data structure
                self._engine.shrinkFloatingBinFunctions(0, num_removed)
            elif lower_part:
                self._remain_size -= num_removed
                # shrink the global data structure
                self._engine.shrinkFloatingBinFunctions(num_removed, 0)

    def checkFinished(self):
        """Check if we finished matching the binary functions, and handles the cleanups needed."""
        if len(filter(lambda ctx: not ctx.matched(), self._bin_functions_ctx)) == 0:
            unused_funcs = set(range(self._src_index_start, self._src_index_end + 1)).difference(self._engine.matchedSrcIndices())
            if len(unused_funcs) > 0:
                self.disableSources(unused_funcs)
                # adjust the limits of the floating file
                floating_representative = self._engine.floatingRepresentative()
                if floating_representative is not None:
                    floating_representative.disableSources(unused_funcs)

    def remove(self, bin_ctx):
        """Remove the given function couple (src index, bin context) from the file's content.

        Args:
            bin_ctx (FunctionContext): (binary) context of the removed (binary) function
        """
        # check if already removed
        if self.located and bin_ctx not in self._bin_functions_ctx:
            return
        # check the floating file
        if not self.located and bin_ctx not in self._engine.floatingBinFunctions():
            return
        # only the first "floating" file is the one that does the actions
        floating_representative = self._engine.floatingRepresentative()
        if not self.located and self != floating_representative:
            floating_representative.remove(bin_ctx)
            return
        # set up the used binary_dictionary
        bin_ctxs = self._bin_functions_ctx if self.located else self._engine.floatingBinFunctions()
        # locate the inner index
        bin_index = bin_ctxs.index(bin_ctx)
        # if the file wasn't yet located there is a reason not to simply do: "lower_part = not upper_part"
        try:
            upper_index = bin_ctxs.index(self._upper_match_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch (%s) remove(): upper match (%s) not in bin_ctxs", self.name, self._upper_match_ctx.name)
            raise AssumptionException()
        try:
            lower_index = bin_ctxs.index(self._lower_match_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch (%s) remove(): lower match (%s) not in bin_ctxs", self.name, self._lower_match_ctx.name)
            raise AssumptionException()
        upper_part = upper_index < bin_index
        lower_part = bin_index < lower_index
        # sanity check - more than the upper leftovers
        if upper_part and self._upper_leftovers is not None and len(bin_ctxs) - bin_index > self._upper_leftovers:
            self._engine.logger.error("Sanity check failed on FileMatch (%s) remove(): %d %d 0x%x %d",
                                                        self.name, bin_index, len(bin_ctxs), bin_ctx.ea, self._upper_leftovers)
            raise AssumptionException()
        # sanity check - more than the lower leftovers
        elif lower_part and self._lower_leftovers is not None and bin_index + 1 > self._lower_leftovers:
            self._engine.logger.error("Sanity check failed on FileMatch (%s) remove(): %d 0x%x %d",
                                                        self.name, bin_index, bin_ctx.ea, self._lower_leftovers)
            raise AssumptionException()
        # Now preform the update itself (changes according to the "type" of the file)
        if self.located:
            if upper_part:
                removed_funcs = self._bin_functions_ctx[bin_index:]
                self._bin_functions_ctx = self._bin_functions_ctx[:bin_index]
                self._upper_leftovers -= len(removed_funcs)
            else:
                removed_funcs = self._bin_functions_ctx[:bin_index + 1]
                self._bin_functions_ctx = self._bin_functions_ctx[bin_index + 1:]
                self._lower_leftovers -= len(removed_funcs)
            # Now update all of the relevant functions that they are expelled from our file
            map(lambda x: x.expel(self), removed_funcs)
            # check if we matched all of our binaries
            self.checkFinished()

    def match(self, src_index, bin_ctx):
        """Notify the file that the given function couple (src index, bin context) was matched.

        Assumptions:
            bin_ctx is contained in the file's list of binary functions

        Args:
            src_index (int): (source) index of the matched (source) function
            bin_ctx (FunctionContext): (binary) context of the matched (binary) function
        """
        # check if this is an internal match or an external remove
        src_ctx = self._engine.src_functions_ctx[src_index]
        if src_index < self._src_index_start or self._src_index_end < src_index:
            self._engine.logger.error("Sanity check failed in FileMatch (%s) match() when matching %s: src index (%d) not in range %d - %d when matching %s",
                                                        self.name, src_ctx.name, src_index, self._src_index_start, self._src_index_end, bin_ctx.name)
            raise AssumptionException()
        # rewire the floating functions back to our file (for adjustments)
        if not self.located:
            self._bin_functions_ctx = self._engine.floatingBinFunctions()
        # special case for partial functions
        if bin_ctx.isPartial():
            # we have one less function to handle, and that's it for this one
            self.markMatch()
            return
        # check for linker optimizations in the same file
        if bin_ctx.merged() and self.index(bin_ctx) is not None:
            self.markMatch()
            return
        # internal match could be: 1) below lower bound 2) above upper bound 3) in the middle
        try:
            bin_index = self._bin_functions_ctx.index(bin_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch (%s) match() when matching %s: matched binary (%s) not in bin_ctxs",
                                                        self.name, src_ctx.name, bin_ctx.name)
            raise AssumptionException()
        link_files = set()
        if len(self._match_sequences) != 0:
            try:
                upper_match_index = self._bin_functions_ctx.index(self._upper_match_ctx)
            except ValueError:
                self._engine.logger.error("Sanity check failed in FileMatch (%s) match() when matching %s: upper match (%s) not in bin_ctxs",
                                                        self.name, src_ctx.name, self._upper_match_ctx.name)
                raise AssumptionException()
            try:
                lower_match_index = self._bin_functions_ctx.index(self._lower_match_ctx)
            except ValueError:
                self._engine.logger.error("Sanity check failed in FileMatch (%s) match() when matching %s: lower match (%s) not in bin_ctxs",
                                                        self.name, src_ctx.name, self._lower_match_ctx.name)
                raise AssumptionException()
        # case #0 - no match yet
        floating_representative = self._engine.floatingRepresentative()
        if not self.located:
            next_representative = self._engine.nextFloatingRepresentative()
            # check if we need to pass the role forward
            if self == floating_representative and next_representative is not None:
                next_representative._lower_match_ctx = self._lower_match_ctx
                next_representative._upper_match_ctx = self._upper_match_ctx
                next_representative._lower_leftovers = self._lower_leftovers
                next_representative._upper_leftovers = self._upper_leftovers
                next_representative._bin_limit_lower = self._bin_limit_lower
                next_representative._bin_limit_upper = self._bin_limit_upper
                floating_representative = next_representative
            # No, just take the information we need form him
            else:
                self._bin_limit_lower = floating_representative._bin_limit_lower
                self._bin_limit_upper = floating_representative._bin_limit_upper
            # not floating anymore
            self._engine.locatedFile(self)
            # now init all of the fields
            self._lower_match_ctx = bin_ctx
            self._upper_match_ctx = bin_ctx
            # we can finaly set the leftovers' values
            self._lower_leftovers = self._lower_match_ctx.index - self._bin_limit_lower
            self._upper_leftovers = self._bin_limit_upper - self._upper_match_ctx.index
            # tell the match that it's mine
            link_files.add(self._bin_functions_ctx[bin_index])
            # mark myself as located
            self.located = True
            self._remain_size = self._src_index_end - self._src_index_start + 1 + self._disabled
            # now adjust the leftovers (and bin functions) according to (potential) prior matches
            for lower_leftovers in xrange(1, self._lower_leftovers):
                if self._engine.binMatched(self._bin_functions_ctx[bin_index - lower_leftovers].ea):
                    self._lower_leftovers = lower_leftovers - 1
                    break
            for upper_leftovers in xrange(1, self._upper_leftovers):
                if self._engine.binMatched(self._bin_functions_ctx[bin_index + upper_leftovers].ea):
                    self._upper_leftovers = upper_leftovers - 1
                    break
            # build an initial list of expelled functions
            expelled_funcs  = self._bin_functions_ctx[:bin_index - self._lower_leftovers]
            expelled_funcs += self._bin_functions_ctx[bin_index + self._upper_leftovers + 1:]
            for expelled_ctx in expelled_funcs:
                expelled_ctx.expel(self)
            self._bin_functions_ctx = [] + self._bin_functions_ctx[bin_index - self._lower_leftovers:bin_index + self._upper_leftovers + 1]
        # case #1
        elif bin_index < lower_match_index:
            self._lower_leftovers -= lower_match_index - bin_index
            self._lower_locked_eas.update(map(lambda ctx: ctx.ea, self._bin_functions_ctx[bin_index + 1:lower_match_index]))
            link_files.update(self._bin_functions_ctx[bin_index:lower_match_index])
            self._lower_match_ctx = bin_ctx
        # case #2
        elif bin_index > upper_match_index:
            self._upper_leftovers -= bin_index - upper_match_index
            self._upper_locked_eas.update(map(lambda ctx: ctx.ea, self._bin_functions_ctx[upper_match_index + 1:bin_index]))
            link_files.update(self._bin_functions_ctx[upper_match_index + 1:bin_index + 1])
            self._upper_match_ctx = bin_ctx
        # case #3
        else:
            link_files.add(self._bin_functions_ctx[bin_index])
            if bin_ctx.ea in self._locked_eas:
                self._locked_eas.remove(bin_ctx.ea)
            elif bin_ctx.ea in self._upper_locked_eas:
                self._upper_locked_eas.remove(bin_ctx.ea)
            elif bin_ctx.ea in self._lower_locked_eas:
                self._lower_locked_eas.remove(bin_ctx.ea)

        # can mark the match now
        self.markMatch()

        # update the floating file
        if floating_representative is not None:
            bin_index = self._engine.floatingBinFunctions().index(bin_ctx)
            # update the bounds of the floating file, in case we matched an extreme binary function
            upper_part = floating_representative._upper_match_ctx.ea < bin_ctx.ea
            lower_part = bin_ctx.ea < floating_representative._lower_match_ctx.ea
            if upper_part:
                purge_size = bin_index - self._engine.floatingBinFunctions().index(floating_representative._upper_match_ctx)
                floating_representative._upper_match_ctx = bin_ctx
                floating_representative._upper_leftovers -= purge_size
                floating_representative._remain_size -= purge_size
            elif lower_part:
                purge_size = self._engine.floatingBinFunctions().index(floating_representative._lower_match_ctx) - bin_index
                floating_representative._lower_match_ctx = bin_ctx
                floating_representative._lower_leftovers -= purge_size
                floating_representative._remain_size -= purge_size

            # update the bounds of the floating file, in case we need to purge out unused leftover functions
            if floating_representative._lower_leftovers > floating_representative._remain_size:
                self._engine.shrinkFloatingBinFunctions(floating_representative._lower_leftovers - floating_representative._remain_size, 0)
            if floating_representative._upper_leftovers > floating_representative._remain_size:
                self._engine.shrinkFloatingBinFunctions(0, floating_representative._upper_leftovers - floating_representative._remain_size)

        # Sanity check
        try:
            bin_index = self._bin_functions_ctx.index(bin_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch (%s) match() when matching %s: matched binary (%s) not in bin_ctxs after update",
                                                        self.name, src_ctx.name, bin_ctx.name)
            raise AssumptionException()
        # now it's safe to preform the cleanup
        self.cleanupMatches(bin_ctx)

        # Now link all of the files (atomically)
        for linked_ctx in link_files:
            linked_ctx.linkFile(self)

    def markMatch(self):
        """Notify the file that there was a match, and that the file leftovers could be adjusted."""
        # we have one less function to handle
        if not self.located:
            self._disabled += 1
            return

        # our file was located
        self._remain_size -= 1

        # shorten the upper leftovers
        expelled_funcs = []
        if self._upper_leftovers > self._remain_size - (len(self._locked_eas) + len(self._lower_locked_eas)):
            delta = self._upper_leftovers - (self._remain_size - (len(self._locked_eas) + len(self._lower_locked_eas)))
            self._upper_leftovers -= delta
            expelled_funcs += self._bin_functions_ctx[-delta:]
            self._bin_functions_ctx = self._bin_functions_ctx[:-delta]
        # shorten the lower leftovers
        if self._lower_leftovers > self._remain_size - (len(self._locked_eas) + len(self._upper_locked_eas)):
            delta = self._lower_leftovers - (self._remain_size - (len(self._locked_eas) + len(self._upper_locked_eas)))
            self._lower_leftovers -= delta
            expelled_funcs += self._bin_functions_ctx[:delta]
            self._bin_functions_ctx = self._bin_functions_ctx[delta:]

        # Now expel all of the functions
        for expelled_ctx in expelled_funcs:
            expelled_ctx.expel(self)

        # check if we matched all of the binaries
        self.checkFinished()
