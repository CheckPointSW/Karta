from collections       import defaultdict
from .pattern_observer import pad
import pickle
import struct
import string
import idc
import sark

###########################
## Static Magic Constant ##
###########################

# If the fptr has no other dptr/fptr in it's scoped range, it will be disqualified as a FP
FPTR_LOCALITY_RANGE = 0x100

###########################
## Static Configurations ##
###########################

# Default paths for storing the state of the observed fptr meta-data (used mainly for debugging)
ref_ptrs_path       = "code_ptrs.bin"
ptr_mappings_path   = "code_ptrs_map.bin"

class FptrIdentifier:
    """A class that collects the information and holds the knowledge we know about local (in-code) constants in the program.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _ref_ptrs (dict): mapping from: clean dest ea ==> original code type
        _ptrs_mappings (dict): mapping from: clean dest ea ==> set of src eas for all of the pointers

    Notes
    -----
        1. A code fptr should point into a code segment.
        2. A code fptr should point into a legal code instruction in the code type that it reflects.
        3. A (safe) code fptr should point to a region of code that looks like a mix of function epilogue/prologue.
        4. A (unsafe) code fptr should match a distance pattern from other safe code fptrs.
        5. A data ptr should point into a data segment.
        6. A data ptr should point into a data-aligned address.
        7. A fptr shouldn't be too far away from other code fptrs / data ptrs / pointed data locations.
    """

    def __init__(self, analyzer):
        """Create the function pointers identifier instance.

        Args:
            analyzer (instance): analyzer instance that we are going to link against
        """
        self._ref_ptrs = {}
        self._ptrs_mappings = defaultdict(set)
        self._analyzer = analyzer

    def store(self):
        """Store the collected fptr features into backup files (used mainly for debugging)."""
        fd = open(ref_ptrs_path, "wb")
        pickle.dump(self._ref_ptrs, fd)
        fd.close()

        fd = open(ptr_mappings_path, "wb")
        pickle.dump(self._ptrs_mappings, fd)
        fd.close()

    def load(self):
        """Load the collected fptrs features from a previous execution (used mainly for debugging).

        Return Value:
            True iff successfully loaded the meta-data
        """
        try:
            self._ref_ptrs = pickle.load(open(ref_ptrs_path, "rb"))
            self._ptrs_mappings = pickle.load(open(ptr_mappings_path, "rb"))
            return False
        except Exception:
            self._ref_ptrs = {}
            self._ptrs_mappings = defaultdict(set)
            return True

    def isPrintableAddress(self, ea):
        """Check if the given address is printable and might be confused with a string.

        Args:
            ea (int): effective address to be checked

        Note:
            We declare the functions in a descending order, to prevent IDA from causing one
            function to swallow other functions. This change significantly improved the quality
            of our analysis.

        Return Value:
            True iff the given address contains only printable chars
        """
        return len(filter(lambda x: x in string.printable, struct.pack("!%s" % (self._analyzer.address_pack_format), ea))) == self._analyzer.addressSize()

    def makePointedFunctions(self):
        """Modify the code and tell IDA that our code fptrs should point to the beginning of functions."""
        # We want the list in descending function order
        fptrs_couples = list(self._ref_ptrs.items())
        fptrs_couples.sort(key=lambda x: x[0], reverse=True)
        # Now we can iterate it
        for func_ea, code_type in fptrs_couples:
            self._analyzer.setCodeType(func_ea, func_ea + 1, code_type)
            idc.MakeFunction(func_ea)

    def checkPointedFunctions(self):
        """Delete all of the function pointers that don't point at a valid function at this state of the analysis.

        Return Value:
            The number of false fptrs that were deleted
        """
        false_ptrs = []
        for func_ea, code_type in self._ref_ptrs.items():
            if not sark.Line(func_ea).is_code:
                false_ptrs.append((func_ea, code_type))
        # now can remove them all
        for ea, code_type in false_ptrs:
            self.deleteFptr(ea, code_type)
        # now fix the gaps too
        for ea, code_type in false_ptrs:
            self._analyzer.setCodeType(ea, ea + self._analyzer.addressSize(), self._analyzer.codeType(ea - 1))
        # return the results
        return len(false_ptrs)

    def isPointedFunction(self, ea):
        """Check if the given effective address is pointed by one of our function pointers.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is pointed by one of our function pointers
        """
        return ea in self._ref_ptrs and self._ref_ptrs[ea] == self._analyzer.codeType(ea)

    def deleteFptr(self, ea, code_type):
        """Delete a function pointer to a given address, and of the given code type."""
        if ea not in self._ref_ptrs or self._ref_ptrs[ea] != code_type:
            return
        self._analyzer.logger.debug("Deleting a FP function pointer to 0x%x (type %d)", ea, code_type)
        self._ref_ptrs.pop(ea)
        for fptr_ea in self._ptrs_mappings[ea]:
            self._analyzer.delCodePtr(fptr_ea, self._analyzer.annotatePtr(ea, code_type))
        self._ptrs_mappings.pop(ea)

    def isValidDataPtr(self, ea, sds):
        """Check if the given effective address could be a valid data pointer.

        Args:
            ea (int): effective address to be checked
            sds (list): list of (sark) data segments

        Return Value:
            True iff the given address could be a valid data pointer
        """
        if ea % self._analyzer.data_fptr_alignment != 0:
            return False
        for sd in sds:
            if sd.startEA <= ea and ea <= sd.endEA:
                return True
        return False

    def isValidCodePtr(self, ea, scs):
        """Check if the given effective address could be a valid code pointer.

        Args:
            ea (int): effective address to be checked
            scs (list): list of (sark) code segments

        Return Value:
            True iff the given address could be a valid code pointer
        """
        if not self._analyzer.isValidCodePtr(ea):
            return False
        for sc in scs:
            if sc.startEA <= ea and ea < sc.endEA:
                return True
        return False

    def locateDataPtrs(self, scs, sds):
        """Locate all data / code fptrs in the given set of segments.

        Args:
            scs (list): list of (sark) code segments
            sds (list): list of (sark) data segments
        """
        local_ref_ptrs = defaultdict(set)
        seen_list = []
        approved_ptrs = []
        approved_eas = set()
        ptrs_mappings = defaultdict(set)
        marked_artifacts = []
        for sd in sds:
            cur_ea = pad(sd.startEA, self._analyzer.data_fptr_alignment)
            while cur_ea < sd.endEA:
                line = sark.Line(cur_ea)
                if line.is_string:
                    cur_ea += pad(line.size, self._analyzer.data_fptr_alignment)
                    continue
                # check for a function ptr
                value = self._analyzer.parseAdderss(cur_ea)
                # make sure it is valid
                if self.isValidCodePtr(value, scs):
                    func_value = self._analyzer.cleanPtr(value)
                    code_type  = self._analyzer.ptrCodeType(value)
                    # is seen
                    if func_value in local_ref_ptrs:
                        local_ref_ptrs[func_value].add(code_type)
                        ptrs_mappings[func_value].add(cur_ea)
                        self._analyzer.logger.debug("Located a fptr from 0x%x to 0x%x (type: %d) - Undeclared function", cur_ea, func_value, code_type)
                        if self.isPrintableAddress(value):
                            self._analyzer.logger.debug("Looks like a printable FP: 0x%x", value)
                        approved_ptrs.append((cur_ea, value))
                        approved_eas.add(cur_ea)
                        seen_list.append((cur_ea, True))
                        marked_artifacts.append((cur_ea, True))
                    # is start of real function, from the correct type
                    elif self._analyzer.codeType(func_value) == code_type and self._analyzer.func_classifier.isFuncStart(func_value):
                        local_ref_ptrs[func_value].add(code_type)
                        ptrs_mappings[func_value].add(cur_ea)
                        self._analyzer.logger.debug("Located a fptr from 0x%x to 0x%x (type: %d) - Existing function", cur_ea, func_value, code_type)
                        approved_ptrs.append((cur_ea, value))
                        approved_eas.add(cur_ea)
                        seen_list.append((cur_ea, True))
                        marked_artifacts.append((cur_ea, True))
                    # is start of function
                    elif self._analyzer.func_classifier.predictFunctionStartMixed(func_value, known_type=code_type):
                        local_ref_ptrs[func_value].add(code_type)
                        ptrs_mappings[func_value].add(cur_ea)
                        self._analyzer.logger.debug("Located a fptr from 0x%x to 0x%x (type: %d) - Undeclared function", cur_ea, func_value, code_type)
                        if self.isPrintableAddress(value):
                            self._analyzer.logger.debug("Looks like a printable FP: 0x%x", value)
                        approved_ptrs.append((cur_ea, value))
                        approved_eas.add(cur_ea)
                        seen_list.append((cur_ea, True))
                        marked_artifacts.append((cur_ea, True))
                    # only a candidate - may be will be approved later
                    else:
                        seen_list.append((cur_ea, False))
                        # check for an analysis problem
                        if list(line.drefs_from) > 0:
                            idc.del_dref(cur_ea, value)
                            idc.del_dref(cur_ea, func_value)
                # Check for a valid data pointer
                elif self.isValidDataPtr(value, sds):
                    # make it a data pointer
                    self._analyzer.markDataPtr(cur_ea, value)
                    self._analyzer.logger.debug("Located a data ptr from 0x%x to 0x%x", cur_ea, value)
                    marked_artifacts.append((cur_ea, False))
                    marked_artifacts.append((value, False))
                # continue forward
                cur_ea += pad(self._analyzer.addressSize(), self._analyzer.data_fptr_alignment)

        # check if there is some pattern we can use to find more fptrs
        chosen_threshold = 7
        cur_window = []
        window_index = 0
        while window_index < len(seen_list):
            # If we didn't reach the end, and
            # 1. The window doesn't have enough "True" pointers
            # 2. The windows contains only "True" pointers
            # Slide the window onward
            while window_index < len(seen_list) and (len(filter(lambda x: x[1], cur_window)) < chosen_threshold or len(filter(lambda x: not x[1], cur_window)) == 0):
                # If we are above the threshold (meaning that cond #2 applies), kick out the first ptr (which is a "True" ptr)
                if chosen_threshold < len(filter(lambda x: x[1], cur_window)):
                    cur_window = cur_window[1:]
                # Add a new pointer at the end of our window
                cur_window.append(seen_list[window_index])
                window_index += 1
            # Sanity check: check if we have a candidate
            if window_index == len(seen_list) and len(filter(lambda x: not x[1], cur_window)) == 0:
                break
            # measure the deltas
            chosen_window = filter(lambda x: x[1], cur_window)
            # deltas between the "True" pointers
            chosen_deltas = set()
            for i in xrange(len(chosen_window) - 1):
                chosen_deltas.add(chosen_window[i + 1][0] - chosen_window[i][0])
            # All possible deltas between adjacent pointers
            seen_deltas = set()
            for i in xrange(len(cur_window) - 1):
                seen_deltas.add(cur_window[i + 1][0] - cur_window[i][0])
            new_chosen = None
            # check for a pattern
            if len(seen_deltas) <= len(chosen_deltas):
                new_chosen = filter(lambda x: not x[1], cur_window)[0]
            # check if the window starts with a candidate, that is right near a "True" pointer
            elif not cur_window[0][1]:
                first_seen = cur_window[0]
                seen_addr = first_seen[0]
                for candidate in [seen_addr - self._analyzer.data_fptr_alignment, seen_addr + self._analyzer.data_fptr_alignment]:
                    if candidate in approved_eas:
                        new_chosen = first_seen
                        break
            # check if found a match
            if new_chosen is not None:
                # re-insert ourselves with our new values
                our_index = cur_window.index(new_chosen)
                cur_window = cur_window[:our_index] + [(new_chosen[0], True)] + cur_window[our_index + 1:]
                # mark the pointer
                cur_ea = new_chosen[0]
                value = self._analyzer.parseAdderss(cur_ea)
                func_value = self._analyzer.cleanPtr(value)
                code_type  = self._analyzer.ptrCodeType(value)
                local_ref_ptrs[func_value].add(code_type)
                ptrs_mappings[func_value].add(cur_ea)
                approved_ptrs.append((cur_ea, value))
                marked_artifacts.append((cur_ea, True))
                approved_eas.add(cur_ea)
                self._analyzer.logger.debug("Located new fptr from 0x%x to 0x%x (type: %d)", cur_ea, func_value, code_type)
            # advance the window
            cur_window = cur_window[1:]

        # filter the pointers (we could have false positives)
        disqualified_addresses = set()
        for cur_ea, raw_address in approved_ptrs:
            fixed_address = self._analyzer.cleanPtr(raw_address)
            disqualified = False
            # check if already disqualified
            if fixed_address not in ptrs_mappings:
                continue
            # Several code types for the same address, we take no chances and remove them all
            if len(local_ref_ptrs[fixed_address]) != 1:
                disqualified = True
            # Check if the code type is even legal for that address
            else:
                wanted_code_type = list(local_ref_ptrs[fixed_address])[0]
                orig_code_type = self._analyzer.codeType(fixed_address)
                idc.MakeUnknown(fixed_address, self._analyzer.addressSize(), 0)
                if orig_code_type != wanted_code_type:
                    self._analyzer.setCodeType(fixed_address, fixed_address + 4, wanted_code_type)
                if idc.MakeCode(fixed_address) == 0:
                    disqualified = True
                # Always clean after ourselves
                idc.MakeUnknown(fixed_address, self._analyzer.addressSize(), 0)
                if orig_code_type != wanted_code_type:
                    self._analyzer.setCodeType(fixed_address, fixed_address + self._analyzer.addressSize(), orig_code_type)
            # We are OK, can continue
            if not disqualified:
                continue
            # Found a false function pointer
            # Be cautious with the removals, we could have duplicates
            if fixed_address in self._ptrs_mappings:
                self._ptrs_mappings.pop(fixed_address)
            disqualified_addresses.add(raw_address)
            marked_artifacts.remove((cur_ea, True))
            # no need to remove from local_ref_ptrs, as the global variable only gets the approved values
            # no need to remove from approved_eas, as this data set isn't used anymore
            self._analyzer.logger.debug("Disqualified (code) pointer 0x%08x from 0x%08x (type %d, seen types %s)", fixed_address, cur_ea, wanted_code_type, local_ref_ptrs[fixed_address])

        # Now filter them based on scoped range from other artifacts
        marked_artifacts.sort(key=lambda x: x[0])
        cur_index = 0
        prev_artifact = None
        while cur_index < len(marked_artifacts) - 1:
            cur_ea, is_fptr = marked_artifacts[cur_index]
            next_ea, _ = marked_artifacts[cur_index + 1]
            # Only check ourselves against the next in line
            if cur_ea + FPTR_LOCALITY_RANGE < next_ea:
                if prev_artifact is None and is_fptr:
                    # we should be disqualified
                    raw_address = self._analyzer.parseAdderss(cur_ea)
                    wanted_code_type = self._analyzer.ptrCodeType(raw_address)
                    fixed_address = self._analyzer.cleanPtr(raw_address)
                    # Be cautious with the removals, we could have duplicates
                    if fixed_address in self._ptrs_mappings:
                        self._ptrs_mappings.pop(fixed_address)
                    disqualified_addresses.add(raw_address)
                    self._analyzer.logger.debug("Disqualified (scope) pointer 0x%08x from 0x%08x (type %d))", fixed_address, cur_ea, wanted_code_type)
                # set the prev artifact
                prev_artifact = None
                # check the next element
                cur_index += 1
            # We are linking to the next element, so he is legit too
            else:
                prev_artifact = next_ea
                cur_index += 1

        # mark the pointers
        for cur_ea, raw_address in filter(lambda x: x[1] not in disqualified_addresses, approved_ptrs):
            self._ref_ptrs[self._analyzer.cleanPtr(raw_address)] = self._analyzer.ptrCodeType(raw_address)
            self._analyzer.markCodePtr(cur_ea, raw_address)

        # print some results
        self._analyzer.logger.info("Found %d different potential function pointer destinations", len(self._ref_ptrs))
