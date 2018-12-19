from core.matching_engine   import MatchEngine
from core.file_layer        import AssumptionException
from config.utils           import *
from file_layer             import FileMatcher
from function_context       import ExternalFunction, SourceContext, BinaryContext, IslandContext
from collections            import defaultdict
import sys

class KartaMatcher(MatchEngine):
    """Complete matching engine logic for Karta, based on the file matching logic of the base MatchEngine

    Attributes:
        _match_round_candidates (list): list of match records, containing all of the valid match candidates for the current matching round
        _match_round_src_index (dict): mapping of the match records for the current matching round: src index => match record
        _match_round_bin_ea (dict): mapping of the match records for the current matching round: bin ea => match record
        _match_round_losers (list): list of match records representing the match round losers (to be tracked for changes)
        _matching_reasons (dict): dictionary of all (non-external) matching reasons: src index => reason
        _src_external_functions (dict): dictionay of all (source) external function: src name => external context
        _ext_unused_functions (set): set of (src) names for unused external functions (all callers were disabled)
        _matching_reason (dict): mapping of all (non-external) matching reasons: src index => reason
        _changed_functions (dict): mappings for hints derived at the current matching round: src index => set of bin function ea
        _once_seen_couples_src (dict): mapping (archive) of all seen matching attempts. Mapping from src index => bin ctx
        _once_seen_couples_bin (dict): mapping (archive) of all seen matching attempts. Mapping from bin ea => src index
        _call_hints_records (list): list of records describing the hints metadata, used as supplementary 
        _anchor_hints (list): holds the hints derived from the anchor matching
        _str_file_hints (set): set of strings that hints about their source code file name
        _bin_suggested_names (dict): suggested names for the matched and unmatched binary functions: ea => name
        _last_matching_step (bool): signals we should try the last matching step
    """
    def __init__(self, logger, disas):
        """Basic Ctor for the matching context

        Args:
            logger (logger): elementals logger instance
            disas (disassembler): disassembler layer handler
        """
        super(KartaMatcher, self).__init__(logger, disas)
        # match round
        self._match_round_candidates  = []
        self._match_round_src_index   = {}
        self._match_round_bin_ea      = {}
        self._match_round_losers      = []
        self._matching_reasons        = {}
        # externals
        self._src_external_functions  = {}
        self._ext_unused_functions    = set()
        # more match mappings
        self._matching_reason         = {}
        # changed / seen records, to track
        self._changed_functions       = defaultdict(set)
        self._once_seen_couples_src   = defaultdict(set)
        self._once_seen_couples_bin   = defaultdict(set)
        self._call_hints_records      = []
        # Data from anchor matching, waiting to be used
        self._anchor_hints            = []
        self._str_file_hints          = set()
        # preparing for the GUI
        self._bin_suggested_names     = {}
        # register our contexts
        registerContexts(SourceContext, BinaryContext, IslandContext)

    # Overriden base function
    def criticalError(self):
        self.logger.error("Encounterred an error, exiting")
        sys.exit(1)

    # Overriden base function
    def declareMatch(self, src_index, func_ea, reason) :
        function_name = self.disas.funcNameEA(func_ea)
        is_anchor = reason in [REASON_ANCHOR, REASON_MANUAL_ANCHOR]

        src_ctx = self.src_functions_ctx[src_index]
        # Sanitation logic that uses contexts (non available in anchor phase)
        if not is_anchor:
            bin_ctx = self.bin_functions_ctx[func_ea]
            # double check the match
            if not bin_ctx.isPartial() and not src_ctx.isValidCandidate(bin_ctx) :
                self.logger.error("Cancelled an invalid match: %s (%d) != 0x%x (%s)", src_ctx.name, src_index, func_ea, function_name)
                raise AssumptionException()
            # no need to declare it twice for anchors
            self.logger.info("Declared a match: %s (%d) == 0x%x (%s)", src_ctx.name, src_index, func_ea, function_name)
            self.logger.debug("Matching reason is: %s", reason)

        # debug sanity checks
        if function_name not in [src_ctx.name, libraryName() + "_" + src_ctx.name] :
            # check if this is an unnamed IDA functions
            if function_name.startswith("sub_") or function_name.startswith("nullsub_") or function_name.startswith("j_") :
                self.logger.debug("Matched to an unknown function: %s (%d) == 0x%x (%s)", src_ctx.name, src_index, func_ea, function_name)
            elif is_anchor or self.bin_functions_ctx[func_ea].isPartial() or (not self.bin_functions_ctx[func_ea].merged()) :
                self.logger.warning("Probably matched a False Positive: %s (%d) == 0x%x (%s)", src_ctx.name, src_index, func_ea, function_name)

        # register the match
        duplicate_match = func_ea in self._bin_matched_ea
        self.function_matches[src_index]  = func_ea
        self._bin_matched_ea[func_ea]     = src_index
        self._matching_reasons[src_index] = reason

        # no need to keep track of the source function any more
        if src_index in self._changed_functions :
            self._changed_functions.pop(src_index)
        if src_index in self._once_seen_couples_src :
            self._once_seen_couples_src.pop(src_index)
        if func_ea in self._once_seen_couples_bin :
            self._once_seen_couples_bin.pop(func_ea)

        # can't continue if an anchor function (the data structures were not built yet)
        if is_anchor :
            self._anchor_hints.append((src_index, func_ea))
            return

        # update the hints now (must be done before we update the files - we need to count in all of the collision candidates)
        self.updateHints(src_index, func_ea)

        # no need to preform these actions twice
        if duplicate_match :
            return

        bin_merged = not bin_ctx.isPartial() and bin_ctx.merged()
        file_list = list(bin_ctx.files) if not bin_ctx.isPartial() else [src_ctx.file]
        collision_file_list = set()
        if bin_merged and len(file_list) > 0:
            match_file = None
            for merged_source_ctx in bin_ctx.merged_sources :
                for file_option in file_list:
                    if file_option._src_index_start <= merged_source_ctx.index and merged_source_ctx.index <= file_option._src_index_end :
                        match_file = file_option
                        # make sure to update that this is the "correct" match (all collissions in the same file are equivelent)
                        src_index = merged_source_ctx.index
                        bin_ctx.match = merged_source_ctx
                        self._bin_matched_ea[func_ea] = merged_source_ctx.index
                        break
                if match_file is not None :
                    break
            # tell the lost files that one of their sources is now gone
            for merged_source_ctx in bin_ctx.merged_sources :
                if merged_source_ctx.file != match_file :
                    merged_source_ctx.file.markMatch()
        else :
            match_file = src_ctx.file
        # update the files
        for file_option in file_list :
            # winner file
            if file_option == match_file :
                match_file.match(src_index, bin_ctx)
            # loser file
            else :
                file_option.remove(bin_ctx)

    # Overriden base function
    def fileLayer(self):
        return FileMatcher

    # Overriden base function
    def loadAndPrepareSource(self, files_config):
        # Prepare & load the stats from each file (using the functions file)
        src_file_names = []
        self.logger.info("Loading the information regarding the compiled source files")
        self.logger.addIndent()
        for full_file_path in files_config :
            self.logger.debug("Parsing the canonical representation of file: %s", full_file_path.split(os.path.sep)[-1])
            src_file_names.append(full_file_path)
            parseFileStats(full_file_path, files_config[full_file_path])
        self.logger.removeIndent()

        # get the variables from the utils file
        self._src_functions_list, self.src_functions_ctx, self._src_file_mappings = getSourceFunctions()

        # prepare a possible collision mapping
        collision_map = defaultdict(list)

        # pre-processed list indices (efficiency improvement)
        func_indices = defaultdict(list)
        for func_idx, func_name in enumerate(self._src_functions_list) :
            func_indices[func_name].append(func_idx)

        # Convert all function calls to contexts instead of names
        self.logger.info("Converting all function references to use the built contexts (instead of string names)")
        src_external_functions = {}
        for src_index, src_func_ctx in enumerate(self.src_functions_ctx) :
            call_name_to_ctx = {}
            # don't forget the file hint string
            str_file_hint = src_func_ctx.checkFileHint()
            if str_file_hint is not None :
                self._str_file_hints.add(str_file_hint)
            # split the functions to internal and external
            src_internal_calls = []
            src_external_calls = []
            src_func_ctx.index = src_index
            for call in src_func_ctx.calls :
                # should make sure to prioritize the call from the same file (duplicates are a nasty edge case)
                if len(func_indices[call]) == 1 :
                    call_src_ctx = self.src_functions_ctx[func_indices[call][0]]
                else :
                    candidates = filter(lambda idx : self.src_functions_ctx[idx].file == src_func_ctx.file, func_indices[call])
                    # duplicate symbol in *other* files, we won't know what to pick up :(
                    if len(candidates) == 0:
                        self.logger.error("Found duplicate implementations of function \"%s\" in files: %s, can't pick one to use :(", call, ', '.join(map(lambda idx : self.src_functions_ctx[idx].file, func_indices[call])))
                        raise KartaException()
                    call_src_ctx = self.src_functions_ctx[candidates[0]]
                call_name_to_ctx[call] = call_src_ctx
                src_internal_calls.append(call_src_ctx)
            for call in src_func_ctx.unknown_funcs:
                if call in libc.skip_function_names or len(call) == 0:
                    continue
                if call not in self._src_external_functions :
                    self._src_external_functions[call] = ExternalFunction(call)
                self._src_external_functions[call].addXref(src_func_ctx)
                src_external_calls.append(self._src_external_functions[call])
            src_func_ctx.calls = set(src_internal_calls)
            src_func_ctx.externals = src_external_calls
            # the call order too
            new_order = {}
            for call in src_func_ctx.call_order :
                if call in libc.skip_function_names or len(call) == 0:
                    continue
                if call in call_name_to_ctx :
                    key =  call_name_to_ctx[call]
                elif call in self._src_external_functions :
                    key = self._src_external_functions[call]
                else : # a global data variable, skip it
                    continue
                new_order[key] = []
                for path in src_func_ctx.call_order[call] :
                    inner_calls = set()
                    for inner_call in path :
                        if inner_call in libc.skip_function_names or len(inner_call) == 0:
                            continue
                        if inner_call in call_name_to_ctx :
                            inner_calls.add(call_name_to_ctx[inner_call])
                        elif inner_call in self._src_external_functions :
                            inner_calls.add(self._src_external_functions[inner_call])
                        else :
                            continue
                    new_order[key].append(inner_calls)
            src_func_ctx.call_order = new_order
            # update the collision mapping
            collision_map[src_func_ctx.hash].append(src_func_ctx)

            # Build up an xref map too
            for call in src_func_ctx.calls :
                call.xrefs.add(src_func_ctx)

        # Tell the possible collision candidates about one another
        for func_hash in collision_map:
            collision_options = collision_map[func_hash]
            for src_func_ctx in collision_options:
                src_func_ctx.markCollisionCandidates(collision_options)

    def prepareBinFunctions(self):
        """Prepares all of the binary contexts for use"""
        
        self.logger.info("Converting all binary function references to use the built contexts (instead of eas)")
        # Traverse all of the contexts of the binary functions, and split them to internal / external calls
        for bin_func_ctx in self.bin_functions_ctx.values() :
            bin_internal_calls = []
            bin_external_calls = []
            for call_ea in bin_func_ctx.calls :
                if call_ea in self.bin_functions_ctx :
                    bin_internal_calls.append(self.bin_functions_ctx[call_ea])
                else :
                    bin_external_calls.append(call_ea)
            bin_func_ctx.calls = set(bin_internal_calls)
            bin_func_ctx.externals = bin_external_calls
            # the call order too
            new_order = {}
            for call_ea in bin_func_ctx.call_order :
                if call_ea in self.bin_functions_ctx :
                    key = self.bin_functions_ctx[call_ea]
                else :
                    key = call_ea
                new_order[key] = []
                for path in bin_func_ctx.call_order[call_ea] :
                    inner_calls = set()
                    for inner_call in path :
                        if inner_call in self.bin_functions_ctx :
                            inner_calls.add(self.bin_functions_ctx[inner_call])
                        else :
                            inner_calls.add(inner_call)
                    new_order[key].append(inner_calls)
            bin_func_ctx.call_order = new_order

            # Build up an xref map too
            for call in bin_func_ctx.calls :
                call.xrefs.add(bin_func_ctx)

            # Now check for outer xrefs
            outer_ref = False
            for ref in filter(lambda x : self.disas.funcAt(x) is not None, self.disas.crefsTo(bin_func_ctx.ea)) :
                if self.disas.funcStart(self.disas.funcAt(ref)) not in self.bin_functions_ctx :
                    outer_ref = True
                    break
            if not outer_ref :
                bin_func_ctx.markStatic()

    def debugPrintState(self, error = False) :
        """Prints a detailed debugging trace of the matching state of each source file, including overall statistics

        Args:
            error (bool, optional): True iff debug printing right before an error exit (False by default)
        """
        # How many functions we've matched?
        num_src_functions  = len(self._src_functions_list) - len(self._src_unused_functions)
        num_act_functions  = num_src_functions - len(filter(lambda x : x.active() and (not x.used()), self.src_functions_ctx))
        num_ext_functions  = len(self._src_external_functions) - len(self._ext_unused_functions)
        self.logger.info("Matched Functions: %d/%d(/%d) (%d/%d)" % (len(self.function_matches), num_src_functions, num_act_functions, len(filter(lambda x : x.matched(), self._src_external_functions.values())), num_ext_functions))
        num_files = 0
        num_ref_files = 0
        located_files = 0
        filled_files  = 0
        filled_ref_files = 0
        for match_file in filter(lambda x : x.valid, self._match_files) :
            num_files += 1
            located_files += (1 if match_file.located   else 0)
            filled_files  += (1 if match_file.matched() else 0)
            reffed_file = False
            missed_ref_func = False
            for src_index in xrange(match_file._src_index_start, match_file._src_index_end + 1) :
                src_ctx = self.src_functions_ctx[src_index]
                if src_ctx.used() :
                    reffed_file = True
                    missed_ref_func = (src_index not in self.function_matches) or missed_ref_func
            num_ref_files    += (1 if reffed_file else 0)
            filled_ref_files += (1 if not missed_ref_func else 0)
        self.logger.info("File Statistics: Located %d/%d files, Finished %d/%d (%d/%d) files", located_files, num_files, filled_files, num_files, filled_ref_files, num_ref_files)
        self.logger.info("------------------------------------------------------------------------")
        printed_ghost = False
        # Source map, by files
        for match_file in filter(lambda x : x.valid, self._match_files) :
            self.logger.info("File: %s (%d %d %d %d)", match_file.name, match_file._remain_size, len(match_file._locked_eas), len(match_file._lower_locked_eas), len(match_file._upper_locked_eas))
            self.logger.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            self.logger.info("Src map:")
            for src_index in xrange(match_file._src_index_start, match_file._src_index_end + 1) :
                candidate_string = ', '.join(map(lambda x : "0x%x" % x.ea, self.src_functions_ctx[src_index].followers))
                if src_index in self._src_anchor_list :
                    self.logger.info("%03d: * (0x%x) - %s", src_index, self.function_matches[src_index], self.src_functions_ctx[src_index].name)
                elif src_index in self.function_matches :
                    self.logger.info("%03d: + (0x%x) - %s", src_index, self.function_matches[src_index], self.src_functions_ctx[src_index].name)
                elif src_index in self._src_unused_functions :
                    self.logger.info("%03d: - %s", src_index, self.src_functions_ctx[src_index].name)
                elif not self.src_functions_ctx[src_index].used() :
                    self.logger.info("%03d: _ - %s", src_index, self.src_functions_ctx[src_index].name)
                elif self.src_functions_ctx[src_index].is_static :
                    self.logger.info("%03d: , - %s", src_index, self.src_functions_ctx[src_index].name)
                else :
                    self.logger.info("%03d: . [%s] - %s", src_index, candidate_string, self.src_functions_ctx[src_index].name)
            self.logger.info("----------------------------------")
            # Bin map
            self.logger.info("Bin map")
            if not match_file.located and printed_ghost :
                self.logger.info("File was not located, see previous such file")
                self.logger.info("==================================")  
                continue
            printed_ghost = printed_ghost or not match_file.located
            # now actually print it
            for bin_ctx in (match_file._bin_functions_ctx if match_file.located else self.floatingBinFunctions()) :
                bin_index = bin_ctx.index
                bin_ea = bin_ctx.ea
                if bin_ctx.call_hints is not None :
                    hints_options = ', '.join(map(lambda x : str(x.index), set(bin_ctx.call_hints)))
                else :
                    hints_options = ''
                if bin_index in self._bin_anchor_list :
                    self.logger.info("%03d: * (0x%x - %s) - (%s)", bin_index, bin_ea, bin_ctx.name, str(match_file.index(bin_ctx)))
                elif bin_ea in self._bin_matched_ea :
                    self.logger.info("%03d: + (0x%x - %s) - (%s)", bin_index, bin_ea, bin_ctx.name, str(match_file.index(bin_ctx)))
                elif not bin_ctx.used() :
                    self.logger.info("%03d: _ (0x%x - %s) [%s]", bin_index, bin_ea, bin_ctx.name, hints_options)
                elif not bin_ctx.is_static :
                    self.logger.info("%03d: & (0x%x - %s)", bin_index, bin_ea, bin_ctx.name)
                else :
                    self.logger.info("%03d: . (0x%x - %s) [%s]", bin_index, bin_ea, bin_ctx.name, hints_options)
            self.logger.info("==================================")    
        self.logger.info("External Functions:")
        for external_func in self._src_external_functions :
            ext_ctx = self._src_external_functions[external_func]
            if ext_ctx.matched() : 
                self.logger.info("+ %s - 0x%x (%s)", ext_ctx.name, ext_ctx.match, self.disas.funcNameEA(ext_ctx.match))
            elif external_func in self._ext_unused_functions :
                self.logger.info("- %s", ext_ctx.name)            
            else :
                self.logger.info(". %s", ext_ctx.name)
        # exit on error
        if error :
            self.logger.error("Internal assumption was broken - probably matched a false positive - exitting")
            return

    def updateHints(self, src_index, func_ea) :
        """Update our knowledge using hints derived from the recent matched function

        Args:
            src_index (int): (source) index of the matched (source) function
            func_ea (int): ea of the (binary) matched function
        """
        src_ctx = self.src_functions_ctx[src_index]
        bin_ctx = self.bin_functions_ctx[func_ea]

        # record the match (also tells my followers tham I'm taken)
        src_ctx.declareMatch(bin_ctx)
        bin_ctx.declareMatch(src_ctx)

        # check for potential merged matches (collision)
        if not bin_ctx.isPartial() and bin_ctx.merged() :
            for collision_candidate in bin_ctx.collision_map[bin_ctx.match.hash] :
                if not collision_candidate.matched() :
                    self.declareMatch(collision_candidate.index, func_ea, REASON_COLLISION)

        # record the instruction ratio sample
        if not bin_ctx.isPartial() :
            recordInstrRatio(self.src_functions_ctx[src_index].instrs, bin_ctx.instrs)

        # record the neighbour statistics
        for src_neighbour in filter(lambda x : 0 <= x and x < len(self._src_functions_list), (src_index - 1, src_index + 1)) :
            # check if the neighbour was matched
            if self.src_functions_ctx[src_neighbour].matched() and not bin_ctx.isPartial() :
                lower = src_neighbour < src_index
                recordNeighbourMatch(is_neighbour = (self.src_functions_ctx[src_neighbour].match.index + (1 if lower else -1)) == bin_ctx.index)

        # function calls
        bin_calls = filter(lambda x : x.active(), bin_ctx.calls)
        src_calls = filter(lambda x : x.active(), src_ctx.calls)
        if len(bin_calls) > 0 and len(src_calls) > 0 :
            # can only continue if this condition does NOT apply because it will cause duplicate "single call" matches
            if not (len(bin_calls) > 1 and len(src_calls) == 1) :
                self._call_hints_records.append((src_calls, bin_calls, src_ctx, bin_ctx, False))
                for call_bin_ctx in bin_calls :
                    call_bin_ctx.addHints(src_calls, True)
            for call_src_ctx in src_calls :
                self._changed_functions[call_src_ctx.index].update(filter(lambda x : call_src_ctx.isValidCandidate(x), bin_calls))
        # function xrefs
        bin_xrefs = filter(lambda x : x.active(), bin_ctx.xrefs)
        src_xrefs = filter(lambda x : x.active(), src_ctx.xrefs)
        if len(bin_xrefs) > 0 and len(src_xrefs) > 0 :
            # can only continue if this condition does NOT apply because it will cause duplicate "single call" matches
            if not (len(bin_xrefs) > 1 and len(src_xrefs) == 1) :
                for xref_bin_ctx in bin_xrefs :
                    xref_bin_ctx.addHints(src_xrefs, False)
            for xref_src_ctx in src_xrefs :
                self._changed_functions[xref_src_ctx.index].update(filter(lambda x : xref_src_ctx.isValidCandidate(x), bin_xrefs))
        # external functions
        bin_exts = filter(lambda ea : ea not in self._bin_matched_ea, bin_ctx.externals)
        src_exts = filter(lambda x : x.active(), src_ctx.externals)
        if len(bin_exts) > 0 and len(src_exts) > 0 :
            self._call_hints_records.append((src_exts, bin_exts, src_ctx, bin_ctx, True))
            # can't continue because it will cause duplicate matches for the same binary
            if len(bin_exts) == 1 and len(src_exts) > 1 :
                return
            for src_ext in src_exts :
                src_ext.addHints(filter(lambda x : self.disas.funcNameEA(x) not in libc.skip_function_names, bin_exts))
                # Check for matches
                matched_ea = src_ext.match
                if matched_ea is not None and matched_ea not in self._bin_matched_ea:
                    self._bin_matched_ea[matched_ea] = self._src_external_functions[src_ext.name]
                    src_ext.ea = matched_ea
                    self._matching_reasons[src_ext.name] = REASON_SINGLE_CALL
                    self.logger.info("Matched external function: %s == 0x%x (%s)", src_ext.name, matched_ea, self.disas.funcNameEA(matched_ea))

    #####################
    ## Matching Rounds ##
    #####################

    def roundMatchResults(self) :
        """Declares the winners of the match round, and prepares for the next round

        Return Value:
            True iff found at least 1 matching couple
        """
        declared_match = False
        matched_src_index = set()
        matched_bin_ea    = set()
        # scan all of the records and decide which will be a real match
        for match_record in self._match_round_candidates :
            # 0. Prepare the variables for easy use
            src_index = match_record['src_index']
            func_ea   = match_record['func_ea']
            src_candidate = self.src_functions_ctx[src_index]
            bin_candidate = self.bin_functions_ctx[func_ea]
            self.logger.debug("Round match attempt: %s (%d) vs %s (0x%x): %f (+%f = %f)" % (src_candidate.name, src_index, bin_candidate.name, bin_candidate.ea, 
                                                                                                match_record['score'] - match_record['boost'], match_record['boost'], match_record['score']))
            # 1. Make sure it is a valid candidate
            if not src_candidate.isValidCandidate(bin_candidate) :
                continue
            # 2. Are we high enough for a match?
            elif match_record['score'] < MINIMAL_MATCH_SCORE :
                # record the loser
                self._match_round_losers.append(match_record)
            # 3. We have a match :)
            else :
                # actually match the couple
                self.logger.debug("Matching in a round match according to score: %f (%f)", match_record['score'] - match_record['boost'], match_record['score'])
                self.declareMatch(src_index, func_ea, match_record['reason'])
                declared_match = True
                # store them for a later filter
                matched_src_index.add(src_index)
                matched_bin_ea.add(func_ea)

        # if this is the last matching step - check if we can find matches in the losers
        if self._last_matching_step:
            matching_src_candidates = []
            matching_bin_candidates = []
            matching_couples = {}
            # We are only searching for used neighbours
            for match_record in self._match_round_losers:
                src_index = match_record['src_index']
                func_ea   = match_record['func_ea']
                src_candidate = self.src_functions_ctx[src_index]
                bin_candidate = self.bin_functions_ctx[func_ea]
                if match_record['boost'] > 0 and src_candidate.used() and bin_candidate.used():
                    # if they are not unique, they both will get disqualified
                    if src_candidate in matching_src_candidates or bin_candidate in matching_bin_candidates:
                        if src_candidate in matching_src_candidates:
                            matching_src_candidates.remove(src_candidate)
                            matching_couples.pop(src_candidate)
                        if bin_candidate in matching_bin_candidates:
                            matching_bin_candidates.remove(bin_candidate)
                    else:
                        matching_src_candidates.append(src_candidate)
                        matching_bin_candidates.append(bin_candidate)
                        matching_couples[src_candidate] = bin_candidate

            # We want that the competitors for each couple, will also be in our list
            for src_candidate in matching_couples:
                bin_candidate = matching_couples[src_candidate]
                # Check the followers hints
                if len(filter(lambda x: x not in matching_bin_candidates, src_candidate.followers)) > 0 :
                    continue
                # Check the xrefs hints
                if len(filter(lambda x: x not in matching_src_candidates, bin_candidate.xref_hints)) > 0 :
                    continue
                # Check the call hints (if have any)
                if bin_candidate.call_hints is not None and len(filter(lambda x: x not in matching_src_candidates, bin_candidate.call_hints)) > 0 :
                    continue
                # We found a match couple
                self.logger.debug("Matching in a round match using the last matching step")
                self.declareMatch(src_candidate.index, bin_candidate.ea, REASON_TRAPPED_COUPLE)
                self._last_matching_step = False
                declared_match = True
                # store them for a later filter
                matched_src_index.add(src_candidate.index)
                matched_bin_ea.add(bin_candidate.ea)

        # filter the losers
        final_loser_list = []
        for loser_record in self._match_round_losers :
            if loser_record['src_index'] in matched_src_index or loser_record['func_ea'] in matched_bin_ea :
                continue
            # check for validity
            if not self.src_functions_ctx[loser_record['src_index']].isValidCandidate(self.bin_functions_ctx[loser_record['func_ea']]) :
                continue
            final_loser_list.append(loser_record)
        self._match_round_losers = final_loser_list

        # empty the rest of the data structures
        self._match_round_candidates = []
        self._match_round_src_index  = {}
        self._match_round_bin_ea     = {}

        # return the final results
        return declared_match

    def recordRoundMatchAttempt(self, src_index, func_ea, score_boost, score, reason) :
        """Records a match attempt into the round's records

        Args:
            src_index (int): (source) index of the candidate (source) function
            func_ea (int): ea of the candidate (binary) function (can't be an island)
            score_boost (int): score boost given to the match attempt because of it's circumstances
            score (int): final matching score (including the score_boost) 
            reason (enum): matching reason, taken from the string enum
        """
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
        if src_index not in self._match_round_src_index :
            self._match_round_src_index[src_index] = match_record
            self._match_round_candidates.append(match_record)
        else :
            prev_record = self._match_round_src_index[src_index]
            # toss duplicates (both ways)
            if prev_record['func_ea'] == match_record['func_ea'] :
                if match_record['score'] <= prev_record['score'] :
                    return
                # we will need this update anyway
                prev_record['score']  = match_record['score']
                prev_record['boost']  = match_record['boost']
                prev_record['reason'] = match_record['reason']
                # be safe with the gaps
                if prev_record['gap-safe'] :
                    # nothing more to be done
                    return
                # still the winner in the binary match - had a gap in the binary or the source
                elif self._match_round_bin_ea[func_ea] == prev_record :
                    # If we won the gap
                    if abs(score - prev_record['gap']) > SAFTEY_GAP_SCORE :
                        prev_record['gap-safe'] = True
                        prev_record['gap'] = None
                        # revive us back
                        self._match_round_candidates.append(prev_record)
                        self._match_round_losers.remove(prev_record)
                    return
                # lost the binary match - match_round_bin_ea[func_ea] != prev_record
                else :
                    prev_bin_record = self._match_round_bin_ea[func_ea]
                    # If we won the gap
                    if abs(score - prev_bin_record['score']) > SAFTEY_GAP_SCORE :
                        prev_record['gap-safe'] = True
                        prev_record['gap'] = None
                        # revive us back (and throw the previous winner)
                        if prev_bin_record['gap-safe'] :
                            prev_bin_record['gap-safe'] = False
                            self._match_round_candidates.remove(prev_bin_record)
                            self._match_round_losers.append(prev_bin_record)
                        self._match_round_bin_ea[func_ea] = prev_record
                        self._match_round_candidates.append(prev_record)
                        self._match_round_losers.remove(prev_record)
                    # check if we are now back the winners of the binary match
                    elif prev_bin_record['score'] < score :
                        self._match_round_bin_ea[func_ea] = prev_record
                        prev_record['gap'] = prev_bin_record['score']
                        if prev_bin_record['gap-safe'] :
                            prev_bin_record['gap-safe'] = False
                            self._match_round_candidates.remove(prev_bin_record)
                            self._match_round_losers.append(prev_bin_record)
            # check if our candidate even needs to compete
            if score + SAFTEY_GAP_SCORE < prev_record['score'] :
                # tough luck, we should get rejected
                match_record['gap-safe'] = False
                self._match_round_losers.append(match_record)
            # both of us lost
            elif abs(score - prev_record['score']) <= SAFTEY_GAP_SCORE :
                match_record['gap-safe'] = False
                self._match_round_losers.append(match_record)
                # remove him only once
                if prev_record['gap-safe'] :
                    prev_record['gap-safe'] = False
                    self._match_round_candidates.remove(prev_record)
                    self._match_round_losers.append(prev_record)
                # check who will be marked as the best loser
                if prev_record['score'] < score :
                    self._match_round_src_index[src_index] = match_record
                    match_record['gap'] = prev_record['score']
                elif prev_record['gap'] is None :
                    prev_record['gap'] = score
                else :
                    prev_record['gap'] = max(score, prev_record['gap'])
            # we won, and we should remember the seen record
            else :
                self._match_round_src_index[src_index] = match_record
                self._match_round_candidates.append(match_record)
                # remove him only once
                if prev_record['gap-safe'] :
                    prev_record['gap-safe'] = False
                    self._match_round_candidates.remove(prev_record)
                    self._match_round_losers.append(prev_record)
                
        # check using the func_ea
        if func_ea not in self._match_round_bin_ea :
            self._match_round_bin_ea[func_ea] = match_record
            # we are in, or we lost, in both cases we shouldn't be added in
        else :
            prev_record = self._match_round_bin_ea[func_ea]
            # check if our candidate even needs to compete
            if score + SAFTEY_GAP_SCORE < prev_record['score'] :
                # tough luck, we should get rejected
                if match_record['gap-safe'] :
                    match_record['gap-safe'] = False
                    self._match_round_candidates.remove(match_record)
                    self._match_round_losers.append(match_record)
            # both of us lost
            elif abs(score - prev_record['score']) <= SAFTEY_GAP_SCORE :
                # remove him only once
                if prev_record['gap-safe'] :
                    prev_record['gap-safe'] = False
                    self._match_round_candidates.remove(prev_record)
                    self._match_round_losers.append(prev_record)
                # remove me only once
                if match_record['gap-safe'] :
                    match_record['gap-safe'] = False
                    self._match_round_candidates.remove(match_record)
                    self._match_round_losers.append(match_record)
                # check who will be marked as the best loser
                if prev_record['score'] < score :
                    self._match_round_bin_ea[func_ea] = match_record
                    match_record['gap'] = prev_record['score']
                elif prev_record['gap'] is None :
                    prev_record['gap'] = score
                else :
                    prev_record['gap'] = max(score, prev_record['gap'])
            # we won, and we should remember the seen record
            else :
                self._match_round_bin_ea[func_ea] = match_record
                # remove him only once
                if prev_record['gap-safe'] :
                    prev_record['gap-safe'] = False
                    self._match_round_candidates.remove(prev_record)
                    self._match_round_losers.append(prev_record)
                # don't add me twice, and don't add me if failed before
        
    def matchAttempt(self, src_index, func_ea, file_match = None) :
        """Attempt to match a source function to code that starts with the given binary ea

        Args:
            src_index (int): (source) index of the candidate (source) function
            func_ea (int): ea of the candidate (binary) function (can't be an island)
            file_match (FileMatch, optional): file in which we are currently trying a geographical match (None by default)

        Return Value:
            True iff we found a match record with high matching probabilities
        """
        # sanity checks
        if src_index < 0 or len(self.src_functions_ctx) <= src_index or src_index in self.function_matches or func_ea in self._bin_matched_ea :
            return False
        src_candidate = self.src_functions_ctx[src_index]
        bin_candidate = self.bin_functions_ctx[func_ea]
        # filter it before giving it a score
        if not src_candidate.isValidCandidate(bin_candidate) :
            return False
        score = src_candidate.compare(bin_candidate, self.logger)
        score_boost = 0
        neighbour_match = False
        # lower neighbour
        if file_match is not None and src_index in file_match._lower_neighbours and file_match._lower_neighbours[src_index][0] == func_ea :
            score_boost += getNeighbourScore()
            neighbour_match = file_match._lower_neighbours[src_index][1]
        # upper neighbour
        if file_match is not None and src_index in file_match._upper_neighbours and file_match._upper_neighbours[src_index][0] == func_ea :
            score_boost += getNeighbourScore()
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
            score_boost += getNeighbourScore()
        # triple the bonus if both apply
        if score_boost >= 2 * getNeighbourScore() :
            score_boost += getNeighbourScore() 
        self.logger.debug("%s (%d) vs %s (0x%x): %f (+%f = %f)" % (src_candidate.name, src_index, bin_candidate.name, bin_candidate.ea, score, score_boost, score + score_boost))
        # record the result (the final decision about it will be received later)
        self.recordRoundMatchAttempt(src_index, func_ea, score_boost, score + score_boost, REASON_NEIGHBOUR if score_boost > 0 else REASON_SCORE)
        # now behave as we expect (unless a better record will win the race)
        if score + score_boost >= MINIMAL_MATCH_SCORE :
            return True
        else :
            # skip bad neighbours
            if file_match is not None and score <= MINIMAL_NEIGHBOUR_THRESHOLD :
                if src_index not in self.function_matches :
                    if self.matchAttempt(src_index + 1, func_ea, file_match) :
                        return True
            return False

    def matchFiles(self) :
        """Main loop responsible for the advancing the matching process"""

        # signal that we haven't arrived yet the last matching step
        self._last_matching_step = False

        # Don't forget all of the hints from the anchors
        for src_index, func_ea in self._anchor_hints :
            self.updateHints(src_index, func_ea)

        # Search for file hint strings, and try to locate more files based on them
        self.logger.info("Searching for file name \"hints\" to thicken the anchors list")
        # traverse all files, and tell them to try and match agents
        for match_file in self._match_files :
            match_file.attemptFindFileHints()
        # handle the match candidates
        try:
            self.roundMatchResults()
        except AssumptionException :
            self.debugPrintState(error = True)
            return

        # merge the results into the changed functions list
        for loser_record in self._match_round_losers :
            src_index = loser_record['src_index']
            func_ea   = loser_record['func_ea']
            self._changed_functions[src_index].add(self.bin_functions_ctx[func_ea])
        # reset the losers list
        self._match_round_losers = []

        # Search for useful "agents" to help the initial anchors list
        self.logger.info("Searching for \"agents\" to thicken the anchors list")
        # traverse all files, and tell them to try and match agents
        for match_file in self._match_files :
            match_file.attemptFindAgents()
        # handle the match candidates
        try:
            self.roundMatchResults()
        except AssumptionException :
            self.debugPrintState(error = True)
            return

        # merge the results into the changed functions list
        for loser_record in self._match_round_losers :
            src_index = loser_record['src_index']
            func_ea   = loser_record['func_ea']
            self._changed_functions[src_index].add(self.bin_functions_ctx[func_ea])
        # reset the losers list
        self._match_round_losers = []

        # print the state before the matching actually starts
        self.debugPrintState()

        self.logger.info("Start the main matching process")
        finished = False
        # while there is work to do
        try :
            while not finished :
                self.logger.debug("Started a matching round")
                finished = True
                # First, Scan all of the (located) files
                for match_file in self._match_files :
                    # tell the file to try and match itself
                    finished = (not match_file.attemptMatches()) and finished

                # Now, check out the changed functions first, and then the once seen functions
                for scoped_functions in [self._changed_functions, self._once_seen_couples_src] :
                    for src_index in list(scoped_functions.keys()) :
                        # Sanity (shouldn't happen): check if already matched
                        if src_index in self.function_matches:
                            continue
                        for bin_ctx in list(scoped_functions[src_index]) :
                            # check if already matched
                            if src_index not in scoped_functions :
                                continue
                            # check if relevant
                            if not self.src_functions_ctx[src_index].isValidCandidate(bin_ctx) :
                                scoped_functions[src_index].remove(bin_ctx)
                                continue
                            # check for a single call hint - this should be a sure match
                            if bin_ctx.call_hints is not None and len(bin_ctx.call_hints) == 1  :
                                self.declareMatch(list(bin_ctx.call_hints)[0].index, bin_ctx.ea, REASON_SINGLE_CALL)
                                finished = False
                                continue
                            # check for a single call hint (collision case) - this should be a sure match
                            if bin_ctx.call_hints is not None and len(bin_ctx.collision_map) > 0 and len(set(map(lambda x : x.hash, bin_ctx.call_hints))) == 1 :
                                # the rest will be taken care by updateHints
                                self.declareMatch(list(bin_ctx.call_hints)[0].index, bin_ctx.ea, REASON_SINGLE_CALL)
                                finished = False
                                continue                   
                            # check for a single xref hint - this should be a sure match
                            if len(set(bin_ctx.xref_hints)) == 1 :
                                self.declareMatch(bin_ctx.xref_hints[0].index, bin_ctx.ea, REASON_SINGLE_XREF)
                                finished = False
                                continue
                            # simply compare them both
                            self.matchAttempt(src_index, bin_ctx.ea)
                            # add it to the once seen couples
                            self._once_seen_couples_src[src_index].add(bin_ctx)
                            self._once_seen_couples_bin[bin_ctx.ea].add(src_index)
                        
                        # if this is first loop, add all of the records from the matching seen couples
                        if scoped_functions == self._changed_functions :
                            for match_record in self._match_round_candidates :
                                # source candidates
                                if match_record['src_index'] in self._once_seen_couples_src :
                                    for bin_ctx in list(self._once_seen_couples_src[match_record['src_index']]) :
                                        if self.src_functions_ctx[match_record['src_index']].isValidCandidate(bin_ctx) :
                                            self.matchAttempt(match_record['src_index'], bin_ctx.ea)
                                        else :
                                            self._once_seen_couples_src[match_record['src_index']].remove(bin_ctx)                            
                                # binary candidates
                                if match_record['func_ea'] in self._once_seen_couples_bin :
                                    for src_index in list(self._once_seen_couples_bin[match_record['func_ea']]) :
                                        if self.src_functions_ctx[src_index].isValidCandidate(self.bin_functions_ctx[match_record['func_ea']]) :
                                            self.matchAttempt(src_index, match_record['func_ea'])
                                        else :
                                            self._once_seen_couples_bin[match_record['func_ea']].remove(src_index)
                            # now reset the dict of changed functions
                            self._changed_functions = defaultdict(set)

                        # check the round results now
                        finished = (not self.roundMatchResults()) and finished

                        # merge the results into the seen couples
                        for loser_record in self._match_round_losers :
                            src_index = loser_record['src_index']
                            func_ea   = loser_record['func_ea']
                            bin_ctx = self.bin_functions_ctx[func_ea]
                            self._once_seen_couples_src[src_index].add(bin_ctx)
                            self._once_seen_couples_bin[bin_ctx.ea].add(src_index)
                        # reset the losers list
                        self._match_round_losers = []
                    
                    # if found a match, break the loop
                    if not finished :
                        break

                # If nothing has changed, check the a hint call order and hope for a sequential tie braker
                if finished :
                    # check for disabled externals
                    for ext_name in self._src_external_functions :
                        ext_ctx = self._src_external_functions[ext_name]
                        if not ext_ctx.used() :
                            self._ext_unused_functions.add(ext_name)
                    new_call_hints_records = []
                    # now match them
                    for src_calls, bin_calls, src_parent, bin_parent, is_ext in self._call_hints_records :
                        # start with a filter
                        if is_ext :
                            src_calls = filter(lambda x : self._src_external_functions[x.name].active() and self._src_external_functions[x.name].used(), src_calls)
                            bin_calls = filter(lambda ea : ea not in self._bin_matched_ea, bin_calls)
                        else :
                            src_calls = filter(lambda x : x.active() and x in src_parent.call_order, src_calls)
                            bin_calls = filter(lambda x : x.active() and x in bin_parent.call_order, bin_calls)
                        if len(src_calls) > 0 and len(bin_calls) > 0 :
                            new_call_hints_records.append((src_calls, bin_calls, src_parent, bin_parent, is_ext))
                        # now continue to the actual logic
                        order_bins = defaultdict(set)
                        order_srcs = defaultdict(set)
                        # build the bin order
                        for bin_ctx in bin_calls :
                            if bin_ctx not in bin_parent.call_order :
                                if not is_ext :
                                    self.logger.warning("Found a probable Island inside function: 0x%x (%s)", bin_ctx.ea, bin_ctx.name)
                                continue
                            for call_path in bin_parent.call_order[bin_ctx] :
                                order_score = len(call_path.intersection(bin_calls))
                                order_bins[order_score].add(bin_ctx)
                        # build the src order
                        for src_ctx in src_calls :
                            for call_path in src_parent.call_order[src_ctx] :
                                order_score = len(call_path.intersection(src_calls))
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
                                self._bin_matched_ea[bin_candidate] = src_candidate
                                src_candidate.ea = bin_candidate
                                self._matching_reasons[src_candidate.name] = REASON_CALL_ORDER
                                self.logger.debug("Matched external through sequential call hints: %s, 0x%x", src_candidate.name, src_candidate.ea)
                                finished = False
                                if src_candidate.hints is not None :
                                    updated_ext_hints = filter(lambda ea : ea not in self._bin_matched_ea, src_candidate.hints)
                                    for src_ext in src_calls :
                                        src_ext.addHints(filter(lambda x : self.disas.funcNameEA(x) not in libc.skip_function_names, updated_ext_hints))
                                        # Check for matches
                                        matched_ea = src_ext.match
                                        if matched_ea is not None and matched_ea not in self._bin_matched_ea:
                                            self._bin_matched_ea[matched_ea] = self._src_external_functions[src_ext.name]
                                            src_ext._ea = matched_ea
                                            self._matching_reasons[src_ext.name] = REASON_SINGLE_CALL
                                            self.logger.info("Matched external function: %s == 0x%x (%s)", src_ext.name, matched_ea, self.disas.funcNameEA(matched_ea))
                            else :
                                # continue on only if the match is valid
                                if src_candidate.isValidCandidate(bin_candidate) :
                                    self.declareMatch(src_candidate.index, bin_candidate.ea, REASON_CALL_ORDER)
                                    finished = False
                    # update the data-structure
                    self._call_hints_records = new_call_hints_records

                # If nothing has changed, check for a function swallowing
                if finished :
                    # find candidates at edges of gaps
                    for match_file in self._match_files :
                        # tell the file to try and search for swallows inside itself
                        if match_file.attemptMatchSwallows() :
                            finished = False

                # Attempt the last matching step - will be done in the round matching itself
                if finished and not self._last_matching_step:
                    self._last_matching_step = True
                    finished = False
        except AssumptionException :
            self.debugPrintState(error = True)
            return

        # check if we actually finished
        success_finish = len(filter(lambda x : x.active(), self._match_files)) == 0
        success_finish = success_finish and len(filter(lambda x : x.active(), self._src_external_functions)) == 0
        if not success_finish :
            # If matched nothing, debug and exit
            self.logger.warning("Completed a full scan without any improvement")
            self.debugPrintState()
        else:
            self.logger.info("Matched all library and external functions :)")

    ######################
    ## Matching Results ##
    ######################

    def prepareGUIEntries(self):
        """Prepares the entries list, according to the sorting logic we want in the GUI

        Return Value:
            (list of source contexts - according to the wanted GUI presentation order, list of similar external contexts)
        """
        # Start with perfect files (sorted by name)
        perfect_files = filter(lambda x : x.matched(), self._match_files)
        perfect_files.sort(key = lambda x : x.name)

        # Now sort the rest according to the number of unmatched "used" source functions
        non_perfect_files = filter(lambda x : x.located and not x.matched(), self._match_files)
        non_perfect_files.sort(key = lambda x : len(filter(lambda c : c.used() and not c.matched(), self.src_functions_ctx[x._src_index_start : x._src_index_end + 1])))

        # now extract the functions, according to their order
        entries = []
        for match_file in perfect_files + non_perfect_files:
            entries += self.src_functions_ctx[match_file._src_index_start : match_file._src_index_end + 1]

        # now the external functions
        external_entries = filter(lambda x : x.matched(), map(lambda x : self._src_external_functions[x], self._src_external_functions))
                
        return entries, external_entries

    def generateSuggestedNames(self):
        """Generates the suggested names for the binary functions"""

        # We have several goals:
        # 0. Clean naming convention - includes the library's name
        # 1. Avoid collisions - same content (hash) in different files
        # 2. Best effort #1 - use file name if known, and function name isn't
        # 3. Best effort #2 - use lib name if a locked function

        rename_file = lambda x : '.'.join(x.split('.')[:-1]).replace(os.path.sep, '_')
        self.logger.info("Generating the suggested names for the located functions")

        # 1. check which (matched) functions share the same name
        matched_src_ctxs = filter(lambda x : x.matched(), self.src_functions_ctx)
        all_match_name = map(lambda x : x.name, matched_src_ctxs)
        duplicate_match_names = filter(lambda x : all_match_name.count(x) > 1, all_match_name)

        # 2. Now rename them if necessary
        for src_ctx in filter(lambda x : x.name in duplicate_match_names, matched_src_ctxs):
            src_ctx.name = rename_file(src_ctx.file.name) + '_' + src_ctx.name

        # 3. Scan all of the files, and name their functions
        for match_file in filter(lambda x : x.valid and x.located, self._match_files) :
            file_name = rename_file(match_file.name)
            for bin_ctx in match_file._bin_functions_ctx :
                # 1. Matched
                if bin_ctx.matched():
                    self._bin_suggested_names[bin_ctx.ea] = libraryName() + '_' + bin_ctx.match.name
                # 2. Single file
                elif len(bin_ctx.files) == 1 :
                    self._bin_suggested_names[bin_ctx.ea] = libraryName() + '_' + file_name.replace("/", "_").replace("\\", "_") + '_' + ('%X' % (bin_ctx.ea))
                # 3. Library related
                else:
                    self._bin_suggested_names[bin_ctx.ea] = libraryName() + '_' + ('%X' % (bin_ctx.ea))

        # 4. Sepcial case for swallows
        for src_ctx in filter(lambda x : self._matching_reasons[x.index] == REASON_SWALLOW, matched_src_ctxs) :
            self._bin_suggested_names[src_ctx.match.ea] = libraryName() + '_' + src_ctx.name

    def showResultsGUIWindow(self, match_entries, external_match_entries):
        """Creates and shows the GUI window containing the match result entries

        Args:
            match_entries (list): list of (src) function contexts, sorted by the presentation order
            external_match_entries (list): list of (external) function contexts, sorted by the presentation order
        """
        prepared_entries = []
        # Prepare the (normal) entries
        for entry in match_entries:
            file_name = '.'.join(entry.file.name.split('.')[:-1])
            src_name  = entry.name
            if entry.matched():
                bin_match = entry.match
                address   = bin_match.ea
                bin_name  = bin_match.name
                reason    = self._matching_reasons[entry.index]
                if reason in [REASON_ANCHOR, REASON_MANUAL_ANCHOR, REASON_AGENT, REASON_FILE_HINT]:
                    color = GUI_COLOR_DARK_GREEN
                else:
                    color = GUI_COLOR_GREEN
            else:
                address = None
                bin_name = 'N/A'
                if entry.index in self._src_unused_functions :
                    reason = REASON_DISABLED
                    color = GUI_COLOR_GRAY
                elif entry.used():
                    reason = 'N/A'
                    color = GUI_COLOR_RED
                elif not entry.is_static:
                    reason = REASON_LIBRARY_UNUSED
                    color = GUI_COLOR_DARK_RED
                else:
                    reason = REASON_STATIC_UNUSED
                    color = GUI_COLOR_DARK_RED
            # Now insert the entry itself
            prepared_entries.append((file_name, src_name, address, bin_name, reason, color))
            
        # show the window
        self.disas.showMatchesForm(prepared_entries, self._bin_suggested_names, self.renameChosenFunctions)

        # Now handle the external entries
        prepared_entries = []
        # Prepare the (external) entries
        for entry in external_match_entries:
            src_name  = entry.name
            address   = entry.match
            bin_name  = self.disas.funcNameEA(address)
            try:
                reason = self._matching_reasons[entry.name]
            except KeyError:
                reason = REASON_SINGLE_CALL
            # Now insert the entry itself
            prepared_entries.append((src_name, address, bin_name, reason, GUI_COLOR_GREEN))
            
        # show the window
        self.disas.showExternalsForm(prepared_entries)

    def renameChosenFunctions(self, bin_eas, suggested_names):
        """Renames the chosed set ot binary functions

        Args:
            bin_eas (list): list of binary eas to be renamed
            suggested_names (dict): suggested names: bin ea => name
        """
        for bin_ea in bin_eas:
            # sanity check
            if bin_ea not in suggested_names:
                self.logger.warning("Failed to rename function at 0x%x, has no name for it", bin_ea)
                continue
            # rename it
            self.disas.renameFunction(bin_ea, suggested_names[bin_ea])
