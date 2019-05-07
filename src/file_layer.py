from core.file_layer    import *
from config.utils       import *
import config.anchor    as anchor

class FileMatcher(FileMatch):
    """A wrapper for Matched Files with an additional matching logic layer.

    Attributes
    ----------
        _unique_strings (list): List of unique string artifacts that were found in the source file
        _unique_consts (list): List of unique numeric const artifacts that were found in the source file
        _lower_neighbours (dict): Mapping of source indices to potential lower neighbour matches: src index => (bin ea, can expand more (True / False))
        _upper_neighbours (dict): Mapping of source indices to potential upper neighbour matches: src index => (bin ea, bool)
    """

    def __init__(self, name, src_index_start, src_index_end, fuzzy_bin_functions_ctx, bin_limit_lower, bin_limit_upper, src_scope, engine):
        """Create a FileMatcher instance according to initial binary bounds and initial anchors matched.

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
        super(FileMatcher, self).__init__(name, src_index_start, src_index_end, fuzzy_bin_functions_ctx, bin_limit_lower, bin_limit_upper, src_scope, engine)
        # list of unique artifacts
        self._unique_strings    = set()
        self._unique_consts     = set()
        # neighbour matching
        self._lower_neighbours  = {}
        self._upper_neighbours  = {}
        # set up the logic needed for the agents
        all_strings = set()
        all_consts  = set()
        for src_ctx in self._engine.src_functions_ctx[self._src_index_start:self._src_index_end + 1]:
            # strings
            self._unique_strings = self._unique_strings.union(src_ctx.strings.difference(all_strings))
            self._unique_strings = self._unique_strings.difference(all_strings.intersection(src_ctx.strings))
            all_strings = all_strings.union(src_ctx.strings)
            # (numeric) consts
            self._unique_consts = self._unique_consts.union(src_ctx.consts.difference(all_consts))
            self._unique_consts = self._unique_consts.difference(all_consts.intersection(src_ctx.consts))
            all_consts = all_consts.union(src_ctx.consts)

    def attemptMatches(self):
        """Attempt to match new functions in the scope of the file.

        Return Value:
            True iff matched at least one function
        """
        match_result = False
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return match_result
        # don't work on unlocated files
        if not self.located:
            return match_result
        # sanity check
        src_index_options = filter(lambda x: x not in self._engine.function_matches, range(self._src_index_start, self._src_index_end + 1))
        if self._remain_size != len(src_index_options):
            self._engine.logger.error("File \"%s\" in attemptMatches(): remain_size (%d) != remaining unmatched src functions (%d)",
                                                    self.name, self._remain_size, len(src_index_options))
            raise AssumptionException()
        # check for a full (src + bin) singleton
        active_bins = filter(lambda ctx: ctx.active(), self._bin_functions_ctx)
        if self._remain_size == 1 and len(active_bins) == 1:
            # we have a singleton - check if it has hints / is it locked
            singleton_ctx = active_bins[0]
            singleton_bin_index = self._bin_functions_ctx.index(singleton_ctx)
            # if used, just match it
            if singleton_ctx.isHinted() or (0 < singleton_bin_index and singleton_bin_index < len(self._bin_functions_ctx) - 1):
                singleton_index = filter(lambda x: x not in self._engine.function_matches, xrange(self._src_index_start, self._src_index_end + 1))[0]
                # check for validity first
                if self._engine.src_functions_ctx[singleton_index].isValidCandidate(singleton_ctx):
                    match_result = self._engine.declareMatch(singleton_index, singleton_ctx.ea, REASON_FILE_SINGLETON) or match_result
        # check for a (locked) bin singleton
        elif len(active_bins) == 1:
            singleton_ctx = active_bins[0]
            singleton_bin_index = self._bin_functions_ctx.index(singleton_ctx)
            # indeed locked
            if 0 < singleton_bin_index and singleton_bin_index < len(self._bin_functions_ctx) - 1:
                singleton_index_options = filter(lambda x: x not in self._engine.function_matches, range(self._src_index_start, self._src_index_end + 1))
                if len(singleton_index_options) > 0:
                    singleton_index = singleton_index_options[0]
                    # try to match it to all remaining source options, and pick the best one
                    best_score = None
                    best_src_index = None
                    prev_match_index = self._engine._bin_matched_ea[self._bin_functions_ctx[singleton_bin_index - 1].ea]
                    for src_index in singleton_index_options:
                        next_match_index = self._engine._bin_matched_ea[self._bin_functions_ctx[singleton_bin_index + 1].ea]
                        # filter it, before giving it a matching score
                        if not self._engine.src_functions_ctx[src_index].isValidCandidate(singleton_ctx):
                            continue
                        cur_score = self._engine.src_functions_ctx[src_index].compare(singleton_ctx, self._engine.logger)
                        # don't forget to boost neighbours
                        cur_score += getNeighbourScore() * [prev_match_index + 1, next_match_index - 1].count(src_index)
                        if best_score is None or cur_score > best_score:
                            best_score = cur_score
                            best_src_index = src_index
                        elif best_score is not None and cur_score == best_score:
                            best_src_index = None  # we have a tie
                        prev_match_index = next_match_index
                    # check if we made it
                    if best_src_index is not None:
                        match_result = self._engine.declareMatch(best_src_index, singleton_ctx.ea, REASON_FILE_SINGLETON) or match_result
        # scan the neighbours for matches, only if it is considered safe
        if not areNeighboursSafe():
            return match_result
        # scan the sequences in search for a potential match
        if len(self._match_sequences) > 1:
            for sequence in self._match_sequences:
                # prefer internal matches
                if sequence == self._match_sequences[0]:
                    self.attemptMatchEnd(sequence)
                elif sequence == self._match_sequences[-1]:
                    self.attemptMatchStart(sequence)
                # normal case
                else:
                    self.attemptMatchStart(sequence)
                    self.attemptMatchEnd(sequence)
        # now check the dangerous leftovers zone
        if len(self._match_sequences) > 0:
            self.attemptMatchStart(self._match_sequences[0])
            self.attemptMatchEnd(self._match_sequences[-1])
        # for a full size match, check the file borders too
        if len(self._bin_functions_ctx) == (self._src_index_end - self._src_index_start + 1):
            # file start
            self._lower_neighbours[self._src_index_start] = (self._bin_functions_ctx[0].ea, False)
            self._engine.matchAttempt(self._src_index_start, self._bin_functions_ctx[0].ea, file_match=self)
            # file end
            self._upper_neighbours[self._src_index_end] = (self._bin_functions_ctx[-1].ea, False)
            self._engine.matchAttempt(self._src_index_end, self._bin_functions_ctx[-1].ea, file_match=self)
        # Return the result
        return match_result

    def attemptMatchStart(self, sequence):
        """Attempt to match a new function from the start (going downwards) of the given match sequence.

        Args:
            sequence (MatchSequence): given match sequence that we are trying to expand downward

        Return Value:
            True iff had a successful attempt to match a function
        """
        try:
            matched_bin_index = self._bin_functions_ctx.index(sequence.bin_lower_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch.attemptMatchStart(): lower ctx (%s) not in bin_ctxs",
                                                sequence.bin_lower_ctx.name)
            raise AssumptionException()
        # can't extend the binary downard
        if matched_bin_index == 0:
            return False
        matched_src_index = sequence.bin_lower_ctx.match.index
        # can't extend the source downard
        if matched_src_index == self._src_index_start:
            return False
        self._lower_neighbours[matched_src_index - 1] = (self._bin_functions_ctx[matched_bin_index - 1].ea, True)
        return self._engine.matchAttempt(matched_src_index - 1, self._bin_functions_ctx[matched_bin_index - 1].ea, file_match=self)

    def attemptMatchEnd(self, sequence):
        """Attempt to match a new function from the end (going upward) of the given match sequence.

        Args:
            sequence (MatchSequence): given match sequence that we are trying to expand upward

        Return Value:
            True iff had a successful attempt to match a function
        """
        try:
            matched_bin_index = self._bin_functions_ctx.index(sequence.bin_upper_ctx)
        except ValueError:
            self._engine.logger.error("Sanity check failed in FileMatch.attemptMatchEnd(): lower ctx (%s) not in bin_ctxs",
                                                sequence.bin_upper_ctx.name)
            raise AssumptionException()
        # can't extend the binary upward
        if matched_bin_index == len(self._bin_functions_ctx) - 1:
            return False
        # can't extend the source upward
        matched_src_index = sequence.bin_upper_ctx.match.index
        if matched_src_index == self._src_index_end:
            return False
        self._upper_neighbours[matched_src_index + 1] = (self._bin_functions_ctx[matched_bin_index + 1].ea, True)
        return self._engine.matchAttempt(matched_src_index + 1, self._bin_functions_ctx[matched_bin_index + 1].ea, file_match=self)

    def attemptFindFileHints(self):
        """Attempt to find matches using file name hint strings."""
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return
        # check if there is a hint pointing at my file
        our_str_hint = None
        for file_hint in self._engine._str_file_hints:
            if self.name.split(os.path.sep)[-1].split('.')[0] == file_hint.split('.')[0]:
                our_str_hint = file_hint
                break
        if our_str_hint is None:
            return
        # now try to match every hinted source function, with every hinted binary functions
        for src_index in xrange(self._src_index_start, self._src_index_end + 1):
            src_ctx = self._engine.src_functions_ctx[src_index]
            # skip matched / unhinted functions
            if not src_ctx.active() or src_ctx.file_hint is None:
                return
            # find the hinted binary candidates
            for bin_ctx in (self._bin_functions_ctx if self.located else self._engine.floatingBinFunctions()):
                # skip unhinted functions
                if our_str_hint not in bin_ctx.strings:
                    continue
                # filter it, before giving it a matching score
                if not src_ctx.isValidCandidate(bin_ctx):
                    continue
                # now attempt to score them (the boost is embedded in the scoring of the matched hint string)
                score = src_ctx.compare(bin_ctx, self._engine.logger)
                # record the result (the final decision about it will be received later)
                self._engine.recordRoundMatchAttempt(src_index, bin_ctx.ea, 0, score, REASON_FILE_HINT)

    def attemptFindAgents(self):
        """Attempt to find "agents" functions according to unique file artifacts."""
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return
        # scan all of the src functions, in search for an agent
        for src_index in xrange(self._src_index_start, self._src_index_end + 1):
            # skip matched functions
            if src_index in self._engine.function_matches:
                continue
            # check if this is an agent
            src_candidate = self._engine.src_functions_ctx[src_index]
            is_string, threshold, agent_criteria = anchor.isAgent(src_candidate, self._unique_strings, self._unique_consts, self._engine.logger)
            if agent_criteria is None:
                continue
            # Now scan the binary functions for a possible match
            for bin_ctx in (self._bin_functions_ctx if self.located else self._engine.floatingBinFunctions()):
                # skip matched functions
                if not bin_ctx.active():
                    continue
                # check if the same criteria works
                if len(set(agent_criteria).intersection(bin_ctx.strings if is_string else bin_ctx.consts)) < threshold:
                    continue
                # be careful with the score boost
                effective_unique_strings = self._unique_strings
                effective_unique_consts  = self._unique_consts
                for file_options in bin_ctx.files:
                    if file_options == self:
                        continue
                    effective_unique_strings = effective_unique_strings.difference(file_options._unique_strings)
                    effective_unique_consts  = effective_unique_consts.difference(file_options._unique_consts)
                double_is_string, double_threshold, double_agent_criteria = anchor.isAgent(src_candidate, effective_unique_strings, effective_unique_consts, self._engine.logger)
                if double_agent_criteria is None or set(agent_criteria).intersection(double_agent_criteria) < double_threshold:
                    score_boost = 0
                else:
                    score_boost = AGENT_BOOST_SCORE
                # filter it, before giving it a matching score
                if not src_candidate.isValidCandidate(bin_ctx):
                    continue
                # now attempt to score them
                score = src_candidate.compare(bin_ctx, self._engine.logger)
                # record the result (the final decision about it will be received later)
                self._engine.recordRoundMatchAttempt(src_index, bin_ctx.ea, score_boost, score + score_boost, REASON_AGENT)

    def attemptMatchSwallows(self):
        """Attempt to match new functions by searching for swallowed functions (islands).

        Return Value:
            True iff matched at least one function
        """
        # can't match anything if already matched them all (or was disabled)
        if not self.active():
            return False
        # scan the src gaps this time
        src_index = self._src_index_start
        first_matched = False
        while src_index <= self._src_index_end:
            # skip if matched
            if src_index in self._engine.function_matches:
                src_index += 1
                first_matched = True
                continue
            if not first_matched:
                src_index += 1
                continue
            gap_index_start = src_index
            gap_index_end = None
            # now search for the gap's end
            src_index += 1
            while src_index <= self._src_index_end:
                if src_index in self._engine.function_matches:
                    gap_index_end = src_index
                    break
                src_index += 1
            # the gap did not end
            if gap_index_end is None:
                return False
            # find the bin size
            gap_bin_start = self._engine.function_matches[gap_index_start - 1]
            gap_bin_end   = self._engine.function_matches[gap_index_end]
            # try to search for a swallow
            if self.attemptMatchSwallow(gap_index_start, gap_index_end - 1, gap_bin_start, gap_bin_end):
                return True
        # Return the result
        return False

    def attemptMatchSwallow(self, src_index_start, src_index_end, lower_bound, upper_bound):
        """Attempt to match new functions by searching for swallowed functions (islands) in a given range.

        Args:
            src_index_start (int): start (source) index of an unmatched (source) gap
            src_index_end (int): end (source) index of an unmatched (source) gap
            lower_bound (int): ea of the lower bound of the gap in the binary address space
            upper_bound (int): ea of the upper bound of the gap in the binary address space

        Return Value:
            True iff matched at least one function
        """
        gap_size = upper_bound - lower_bound
        # sanity check - should not happen
        if gap_size <= 0:
            return False
        # check all of the options in the source gap
        for src_index in xrange(src_index_start, src_index_end + 1):
            # check for a single xref source function
            src_candidate_ctx = self._engine.src_functions_ctx[src_index]
            if len(src_candidate_ctx.xrefs) != 1:
                continue
            # check if the xref was matched already (we can't advance otherwise)
            src_parent = list(src_candidate_ctx.xrefs)[0]
            if not src_parent.matched():
                continue
            # now check if there is a floating chunk inside this gap
            bin_parent = src_parent.match
            # make sure (sanity check) that bin_parent is not inside our gap
            if lower_bound <= bin_parent.ea and bin_parent.ea <= upper_bound:
                continue
            island_blocks = self._engine.disas.searchIslands(bin_parent.ea, lower_bound, upper_bound)
            # Failed to find a match
            if island_blocks is None:
                return False
            # We have a list of linked external blocks, that are linked to the parent function, and were found in our gap => Jackpot
            island_ctx = self._engine.disas.analyzeIslandFunction(island_blocks)
            island_ctx.preprocess()
            # Fix it's externals
            bin_internal_calls = []
            bin_external_calls = []
            for call_ea in island_ctx.calls:
                if call_ea in self._engine.bin_functions_ctx.keys():
                    bin_internal_calls.append(self._engine.bin_functions_ctx[call_ea])
                else:
                    bin_external_calls.append(call_ea)
            island_ctx.calls = bin_internal_calls
            island_ctx.externals = bin_external_calls
            # score it up and check for a match (no need to filter this option, it's a swallow)
            score = island_ctx.compare(src_candidate_ctx, self._engine.logger)
            if src_index == src_index_start or src_index == src_index_end:
                score += getNeighbourScore()
            if score >= MINIMAL_ISLAND_SCORE:
                self._engine.bin_functions_ctx[island_ctx.ea] = island_ctx
                self._engine.declareMatch(src_candidate_ctx.index, island_ctx.ea, REASON_SWALLOW)
                return True
        return False
