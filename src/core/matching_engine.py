from config.utils    import *
from core.file_layer import AssumptionException
import config.anchor as anchor
import time

class MatchEngine(object):
    """A class that handles the book-keeping for the matching process

    Attributes:
        logger (logger): elementals logger instance
        disas (disassembler): disassembler layer handler
        src_functions_ctx (list): orderred list of source function contexts
        bin_functions_ctx (dict): mapping of binary address to binary context: bin ea => bin function ctx
        function_matches (dict): mapping of all (non-external) matches: src index => bin ea
        _floating_bin_functions (list): list of all of the binary function contexts in the total range of the floating files
        _floating_files (list): orderred list of currently floating files (FileMatch instances)
        _src_unused_functions (set): set of (src) indices for unused functions (disabled functions)
        _src_functions_list (list): orderred list of source function names
        _src_file_mappings (dict): mapping of file name => list of source function contexts
        _match_files (list): list of FileMatch instances, one for every source file
        _src_file_names (list): list of active (non-empty) source file names
        _bin_matched_ea (dict): reverse mapping for all matches: bin ea => src index / external ctx
        _matched_anchors_ea (dict): matching mapping for the anchor functions: src index ==> bin ea
        _src_anchor_list (list): list of source indices for the matched anchor functions
        _bin_anchor_list (list): sorted list of binary indices of the matched anchor functions
    """

    def __init__(self, logger, disas):
        """Basic Ctor for the matching context

        Args:
            logger (logger): elementals logger instance
            disas (disassembler): disassembler layer handler
        """
        self.logger                     = logger
        self.disas                      = disas
        self.function_matches           = {}
        self.src_functions_ctx          = []
        self.bin_functions_ctx          = {}
        self._floating_bin_functions    = None
        self._floating_files            = []
        self._src_unused_functions      = set()
        self._src_functions_list        = []
        self._src_file_mappings         = {}
        self._match_files               = []
        self._src_file_names            = []
        self._bin_matched_ea            = {}
        self._matched_anchors_ea        = {}
        self._src_anchor_list           = []
        self._bin_anchor_list           = []

    def binMatched(self, ea):
        """Checks if the given effective address was already matched

        Return Value:
            True if ea was matched to some source function
        """
        return ea in self._bin_matched_ea

    def matchedSrcIndices(self):
        """Returns a list of all indices of matched source functions

        Return Value:
            list of source indices for matched functions
        """
        return self.function_matches.keys()

    def floatingBinFunctions(self):
        """Returns an orderred list of all scoped (floating) binary contexts

        Return Value:
            list of all floating binary contexts
        """
        return self._floating_bin_functions

    def floatingRepresentative(self):
        """Returns the FileMatch instance that represents all of the floating files

        Return Value:
            representative floating file instance, or None if there is no such file
        """
        if len(self._floating_files) > 0 :
            return self._floating_files[0]
        else:
            return None

    def nextFloatingRepresentative(self):
        """Returns a FileMatch instance that is next-in-line to represent the floating files

        Return Value:
            next-representative floating file instance, or None if there is no such file
        """
        if len(self._floating_files) > 1 :
            return self._floating_files[1]
        else:
            return None

    def markUnused(self, src_indices):
        """Marks a collection of source functions as unused (ifdeffed / inlined), based on their source indices

        Args:
            src_indices (collection): collection of source indices of the (now) unused functions
        """
        self._src_unused_functions.update(src_indices)
        for src_index in src_indices:
            self.src_functions_ctx[src_index].disable()

    def shrinkFloatingBinFunctions(self, lower_cut, upper_cut):
        """Shrinks the focused scope of binary functions used for representing the overall floating file

        Args:
            lower_cut (int): number of functions to be removed from the lower end
            upper_cut (int): number of functions to be removed from the upper end
        """
        # No need to actually expel() these, as we just purged them from our working set.
        #   expelled_funcs = floating_bin_functions[ : lower_cut] + floating_bin_functions[-1 * upper_cut : ]
        # This line means we simply won't see them anymore and that's it
        if upper_cut == 0 :
            self._floating_bin_functions = self._floating_bin_functions[lower_cut :]
        elif lower_cut == 0 :
            self._floating_bin_functions = self._floating_bin_functions[: -1 * upper_cut]
        else :
            self._floating_bin_functions = self._floating_bin_functions[lower_cut : -1 * upper_cut]
        # update the floating representative file
        floating_representative = self.floatingRepresentative()
        if upper_cut != 0 :
            floating_representative._upper_leftovers -= upper_cut
            floating_representative._bin_limit_upper -= upper_cut
        elif lower_cut != 0 :
            floating_representative._lower_leftovers -= lower_cut
            floating_representative._bin_limit_lower += lower_cut

    def locatedFile(self, file_match):
        """Marks a given file as "located", i.e. not floating any more

        Args:
            file_match (FileMatch): source file that was now pinned to a given place in the memory space
        """
        self._floating_files.remove(file_match)

    def loadAndMatchAnchors(self, anchors_config, manual_anchors_config):
        """Loads the list of anchor functions, and try to match them with the binary

        Args:
            anchors_config (list): list of anchor src indices
            manual_anchors_config (list): list of user defined matches (Manual Anchors): (src index, bin_ea)
        """
        # Parse the anchors file
        self.logger.info("Loading the list of Anchor functions")
        self._src_anchor_list = anchors_config

        # Locate the anchor functions
        self.logger.info("Searching for the Anchor functions in the binary")
        self.logger.addIndent()
        all_bin_functions = self.disas.functions()
        # range narrowing variables
        lower_match_ea = None
        upper_match_ea = None
        lower_match_index = None
        upper_match_index = None
        lower_border_ea = 0
        upper_border_ea = 2 ** 64 - 1
        lower_border_index = None
        upper_border_index = None
        function_range = None
        overall_num_functions = len(self._src_functions_list)
        multiple_option_candidates = []
        anchor_eas = []
        first_const_anchor = True
        efficient_const_search = False
        # pre-scan (for optimization reasons)
        anchor_stats = []
        num_const_clues  = 0
        all_const_clues  = set()
        all_string_clues = set()
        seen_strings, seen_consts, function_list = getContextsStats()
        for src_anchor_index in list(self._src_anchor_list) :
            src_func_ctx = self.src_functions_ctx[src_anchor_index]
            is_str, threshold, anchor_clues = anchor.isAnchor(src_func_ctx, seen_strings, seen_consts, function_list, self.logger)
            # sanity check
            if anchor_clues is None :
                self._src_anchor_list.remove(src_anchor_index)
                self.logger.warning("Anchor candidate %s (%d) failed as an anchor function", src_func_ctx.name, src_anchor_index)
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
            for bin_str_ctx in self.disas.strings() :
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
                            for ref in self.disas.drefsTo(bin_str.ea) :
                                caller_func = self.disas.funcAt(ref)
                                if caller_func is None :
                                    continue
                                callar_func_start = self.disas.funcStart(caller_func)
                                if lower_border_ea <= callar_func_start and callar_func_start <= upper_border_ea :
                                    current_set.add(callar_func_start)
                # consts
                else :
                    # measure some times (for the first one only)
                    if first_const_anchor :
                        start_time = time.time()
                    # scanning the entire firmware per anchor const - O(kN)
                    current_set = set()
                    # search for it in the binary (non efficient)
                    if lower_match_index is None or not efficient_const_search :
                        search_start = lower_border_ea if not first_const_anchor else 0
                        search_end   = upper_border_ea if not first_const_anchor else (2 ** 64 - 1)
                        # start our search
                        for match_ea in self.disas.findImmediate(search_start, search_end, clue):
                            # Filter out matches that are not inside functions
                            caller_func = self.disas.funcAt(match_ea)
                            if caller_func is not None :
                                current_set.add(self.disas.funcStart(caller_func))
                        # measure the end time too
                        if first_const_anchor :
                            end_time = time.time()
                            overall_search_time = (end_time - start_time) * num_const_clues
                            if lower_match_index is None :
                                efficient_const_search = anchor.MAXIMAL_CONST_SEARCH_TIME <= overall_search_time
                            else :
                                efficient_const_search = anchor.MAXIMAL_CONST_SEARCH_RATE <= overall_search_time * 1.0 / (upper_match_index - lower_match_index + 1)
                            # no longer the first const
                            first_const_anchor = False
                    # efficient search
                    else :
                        if function_range is None :
                            self.logger.info("Anchor search - switching to efficient const search mode")
                            # build the fast mapping, and then continue as before
                            function_range = []
                            for function_ea in all_bin_functions[lower_border_index : upper_border_index] :
                                function_range.append((function_ea, self.disas.locateAnchorConsts(function_ea, all_const_clues)))  
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
                self.logger.warning("Anchor function - %s: Failed to find a match", self._src_functions_list[src_anchor_index])
                self._src_anchor_list.remove(src_anchor_index)
            elif len(candidates) == 1 :
                caller_func = self.disas.funcAt(candidates.pop())
                caller_func_start = self.disas.funcStart(caller_func)
                self.logger.info("Anchor function - %s: Matched at 0x%x (%s)", self._src_functions_list[src_anchor_index], caller_func_start, self.disas.funcName(caller_func))
                self._matched_anchors_ea[src_anchor_index] = caller_func_start
                anchor_eas.append(caller_func_start)
                self.declareMatch(src_anchor_index, caller_func_start, REASON_ANCHOR)
                # use the match to improve our search range
                # first anchor
                if len(self._matched_anchors_ea.keys()) == 1 :
                    lower_match_ea = caller_func_start
                    upper_match_ea = lower_match_ea
                    lower_match_index = all_bin_functions.index(caller_func_start)
                    upper_match_index = lower_match_index
                    change = True
                else :
                    # try to improve the lower border
                    if caller_func_start < lower_match_ea :
                        lower_match_ea = caller_func_start
                        new_lower_index = all_bin_functions.index(caller_func_start)
                        if function_range is not None :
                            function_range = function_range[new_lower_index - lower_match_index : ]
                        lower_match_index = new_lower_index
                        change = True
                    # try to improve the lower border
                    elif upper_match_ea < caller_func_start :
                        upper_match_ea = caller_func_start
                        new_upper_index = all_bin_functions.index(caller_func_start)
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
                    lower_border_ea = all_bin_functions[max(lower_match_index - (overall_num_functions - locked_gap), 0)]
                    upper_border_ea = all_bin_functions[min(upper_match_index + (overall_num_functions - locked_gap), len(all_bin_functions) - 1)]
            else :
                self.logger.warning("Anchor function - %s: Found several matches (%d), will check it again later", self._src_functions_list[src_anchor_index], len(candidates))
                multiple_option_candidates.append((src_anchor_index, candidates))
        self.logger.removeIndent()

        # good time to match the user declared functions
        for src_index, bin_ea in manual_anchors_config :
            # check for user errors
            func_ctx = self.disas.funcAt(bin_ea)
            if func_ctx is None or self.disas.funcStart(func_ctx) != bin_ea:
                self.logger.warning("User defined anchor function %s should be matched to a *start* of a function, not to 0x%x (%s)", self._src_functions_list[src_index], bin_ea, self.disas.funcNameEA(bin_ea))
                continue
            # check for duplicates
            if src_index in self._matched_anchors_ea :
                # contradiction
                if bin_ea != self._matched_anchors_ea[src_index]:
                    actual_ea = self._matched_anchors_ea[src_index]
                    self.logger.warning("User defined anchor function %s contradicts match at 0x%x (%s), ignoring user definition", self._src_functions_list[src_index], actual_ea, self.disas.funcNameEA(actual_ea))
                    continue
                # duplicate
                else:
                    continue
            # duplicate at this point could only be a contradiction
            if bin_ea in anchor_eas and src_index not in self._matched_anchors_ea :
                self.logger.warning("User defined anchor function %s contradicts match at 0x%x (%s), ignoring user definition", self._src_functions_list[src_index], bin_ea, self.disas.funcNameEA(bin_ea))
                continue
            # can now safely declare this match
            self.logger.info("User defined anchor function - %s: Matched at 0x%x (%s)", self._src_functions_list[src_index], bin_ea, self.disas.funcNameEA(bin_ea))
            self._matched_anchors_ea[src_index] = bin_ea
            anchor_eas.append(bin_ea)
            self._src_anchor_list.append(src_index)
            self.declareMatch(src_index, bin_ea, REASON_MANUAL_ANCHOR)
            # use the match to improve our search range
            # first anchor
            if len(self._matched_anchors_ea.keys()) == 1 :
                lower_match_ea = bin_ea
                upper_match_ea = lower_match_ea
                lower_match_index = all_bin_functions.index(bin_ea)
                upper_match_index = lower_match_index
                change = True
            else :
                # try to improve the lower border
                if bin_ea < lower_match_ea :
                    lower_match_ea = bin_ea
                    new_lower_index = all_bin_functions.index(bin_ea)
                    if function_range is not None :
                        function_range = function_range[new_lower_index - lower_match_index : ]
                    lower_match_index = new_lower_index
                    change = True
                # try to improve the lower border
                elif upper_match_ea < bin_ea :
                    upper_match_ea = bin_ea
                    new_upper_index = all_bin_functions.index(bin_ea)
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
                lower_border_ea = all_bin_functions[max(lower_match_index - (overall_num_functions - locked_gap), 0)]
                upper_border_ea = all_bin_functions[min(upper_match_index + (overall_num_functions - locked_gap), len(all_bin_functions) - 1)]

        # double check the candidates which had multiple options (if narrowed the search space)
        if lower_match_ea is not None :
            for src_anchor_index, candidates in multiple_option_candidates :
                # check if the manual definitions already defined this one
                if src_anchor_index in self._matched_anchors_ea:
                    continue
                filterred_candidates = filter(lambda x : lower_match_ea <= x and x <= upper_match_ea, candidates)
                # matched
                if len(filterred_candidates) == 1 :
                    bin_ea = filterred_candidates.pop()
                    if bin_ea in anchor_eas:
                        self.logger.warning("User defined anchor function at 0x%x (%s), blocked revived anchor: %s, dropped the anchor", bin_ea, self.disas.funcNameEA(bin_ea), self._src_functions_list[src_anchor_index])
                        self._src_anchor_list.remove(src_anchor_index)
                        continue
                    caller_func = self.disas.funcAt(bin_ea)
                    caller_func_start = self.disas.funcStart(caller_func)
                    self.logger.info("Anchor function (revived) - %s: Matched at 0x%x (%s)", self._src_functions_list[src_anchor_index], caller_func_start, self.disas.funcName(caller_func))
                    self._matched_anchors_ea[src_anchor_index] = caller_func_start
                    anchor_eas.append(caller_func_start)
                    self.declareMatch(src_anchor_index, caller_func_start, REASON_ANCHOR)
                # still not found
                else :
                    self._src_anchor_list.remove(src_anchor_index)

        # make sure we found atleast one anchor function
        if len(self._src_anchor_list) == 0 :
            self.logger.error("Failed to match even a single Anchor function")
            raise KartaException

        # Create a binary anchor list for future use
        self._bin_anchor_list = []
        for src_anchor_index in self._src_anchor_list :
            self._bin_anchor_list.append(all_bin_functions.index(self.function_matches[src_anchor_index]))

        # Sort the file list according to the (bin) order of the anchors    
        old_anchor_list = list(self._src_anchor_list)
        self._src_anchor_list.sort(key = lambda x : self._bin_anchor_list[old_anchor_list.index(x)])

        # Sanity Check: make sure that the files are not mixed up
        anchor_files = []
        started = True
        for src_anchor_index in self._src_anchor_list :
            if not started and self.src_functions_ctx[src_anchor_index].file != anchor_files[-1] :
                if self.src_functions_ctx[src_anchor_index].file in anchor_files :
                    self.logger.error("Sanity check failed: the matched anchor functions are tangled between files...")
                    raise KartaException
            if self.src_functions_ctx[src_anchor_index].file not in anchor_files :
                anchor_files.append(self.src_functions_ctx[src_anchor_index].file)
            started = False

        # remove empty files (wierd edge case)
        self._src_file_names = filter(lambda x : len(self._src_file_mappings[x]) != 0, self._src_file_mappings.keys())
        removed_names  = filter(lambda x : len(self._src_file_mappings[x]) == 0, self._src_file_mappings.keys())
        for name in removed_names :
            self._src_file_mappings.pop(name)

        # Now sort the src file names list according to the sorted anchors
        self._src_file_names = anchor_files + list(set(self._src_file_names).difference(anchor_files))

    def locateFileBoundaries(self):
        """Uses the anchors to create initial file borders in the binary address space"""

        self.logger.info("Zooming-in to define the tentative borders for each source file in the binary address space")
        # Split the matched anchor functions to their respective files
        file_to_anchor_mapping = {}
        for path in self._src_file_names :
            file_to_anchor_mapping[path] = []
            for src_ctx in self._src_file_mappings[path] :
                if src_ctx.index in self._matched_anchors_ea :
                    file_to_anchor_mapping[path].append(src_ctx)

        # construct the list of minimal bound and maximal bound for each file
        # this could be tricky since not all of our files are going to have anchor functions - including the first and the last file
        all_bin_functions = self.disas.functions()
        file_min_bound = []
        file_max_bound = []
        file_lower_gap = []
        file_upper_gap = []
        first_anchor_index = None
        last_anchor_index  = None
        overall_min_bin_anchor_index = None
        overall_max_bin_anchor_index = None
        # 1st round, basic estimates using only the anchors (files without anchors are placed artificialy at the end)
        for file_index, file_name in enumerate(self._src_file_names) :
            # return back to this file after the initial round
            if len(file_to_anchor_mapping[file_name]) == 0 :
                break
            if first_anchor_index is None :
                first_anchor_index = file_index
            last_anchor_index = file_index
            # else, we have an anchor, and we can have basic bounds for now
            min_anchor = min(map(lambda x : self._matched_anchors_ea[x.index], file_to_anchor_mapping[file_name]))
            max_anchor = max(map(lambda x : self._matched_anchors_ea[x.index], file_to_anchor_mapping[file_name]))
            min_anchor_bin_index = all_bin_functions.index(min_anchor)
            max_anchor_bin_index = all_bin_functions.index(max_anchor)
            if overall_min_bin_anchor_index is None :
                overall_min_bin_anchor_index = min_anchor_bin_index
                overall_max_bin_anchor_index = max_anchor_bin_index
            else :
                overall_min_bin_anchor_index = min(overall_min_bin_anchor_index, min_anchor_bin_index)
                overall_max_bin_anchor_index = max(overall_max_bin_anchor_index, max_anchor_bin_index)
            base_leftover_size = len(self._src_file_mappings[file_name]) - (max_anchor_bin_index - min_anchor_bin_index + 1)
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
        overall_num_functions = len(self._src_functions_list)
        num_locked_functions = max(self._bin_anchor_list) - min(self._bin_anchor_list) + 1
        remain_source_funcs = overall_num_functions - num_locked_functions
        bin_start_index = max(overall_min_bin_anchor_index - remain_source_funcs, 0)
        bin_end_index   = min(overall_max_bin_anchor_index + remain_source_funcs, len(all_bin_functions) - 1)
        self.logger.info("Analyzing all of the binary functions in the chosen scope")
        # prepare all of the functions
        for bin_index, func_ea in enumerate(all_bin_functions[bin_start_index : bin_end_index + 1]) :
            self.bin_functions_ctx[func_ea] = self.disas.analyzeFunction(func_ea, False)
            self.bin_functions_ctx[func_ea].index = bin_start_index + bin_index
            self.bin_functions_ctx[func_ea].preprocess()

        self.logger.info("Linking the binary functions to their respective tentative files")
        # Can now slice it up and build the FileMatch structure
        file_class = self.fileLayer()
        for file_index, file_name in enumerate(self._src_file_names) :
            # source indices
            src_start_index = self._src_file_mappings[file_name][0].index
            src_end_index   = self._src_file_mappings[file_name][-1].index
            # check if this file wasn't located yet
            if len(file_to_anchor_mapping[file_name]) == 0 :
                # a "floating" file that will hold the entire binary functions as possible candidates
                if self._floating_bin_functions is None :
                    self._floating_bin_functions = map(lambda ea : self.bin_functions_ctx[ea], all_bin_functions[bin_start_index : bin_end_index + 1])
                file_match = file_class(file_name, src_start_index, src_end_index, None, bin_start_index, bin_end_index, remain_source_funcs, self)
                self._floating_files.append(file_match)
            else:
                # binary indices
                local_bin_start_index = file_min_bound[file_index]
                local_bin_end_index   = file_max_bound[file_index]
                # sanity check
                if local_bin_start_index > local_bin_end_index :
                    self.logger.error("File \"%s\" was found at 0x%x, but contains negative amount of functions. Please improve the function analysis", file_name, all_bin_functions[local_bin_start_index])
                    raise KartaException
                # scoped binary functions
                local_bins_ctx = map(lambda ea : self.bin_functions_ctx[ea], all_bin_functions[local_bin_start_index : local_bin_end_index + 1])
                file_match = file_class(file_name, src_start_index, src_end_index, local_bins_ctx, local_bin_start_index, local_bin_end_index, src_end_index - src_start_index + 1, self)
            # add this file instance to the list
            self._match_files.append(file_match)
            # connect the source functions to the file too
            for src_ctx in self._src_file_mappings[file_name] :
                src_ctx.file = self._match_files[file_index]

    def fileLayer(self):
        """Returns the basic class used for the file layer (FileMatch by default)"""
        return FileMatch

    def declareMatch(self, src_index, func_ea, reason) :
        """Officially declare a match of a source function to code that starts with the given binary ea

        Args:
            src_index (int): (source) index of the matched (source) function
            func_ea (int): ea of the matched (binary) function (maybe an island)
            reason (enum): matching reason, taken from the string enum options
        """
        raise NotImplementedError("Subclasses should implement this!")
        
    def criticalError(self):
        """Critical error that mandates we exit WITHOUT showing partial results to the user, we must exit now"""
        raise NotImplementedError("Subclasses should implement this!")

    def loadAndPrepareSource(self, files_config):
        """Loads the stored info on the source files, and prepares the source contexts for use

        Args:
            files_config (dict): the files configuration part of the overall JSON config
        """
        raise NotImplementedError("Subclasses should implement this!")
