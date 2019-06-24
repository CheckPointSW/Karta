from .pattern_observer import pad
import idc
import sark

class LocalsIdentifier:
    """A class that collects the information and holds the knowledge we know about local (in-code) constants in the program.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _local_alignment (int): byte alignment for the "local" constants - constants that appear in code segments
        _local_pad (int): numeric value of the padding byte of local constants, if one exists (None otherwise)

    Notes
    -----
        It is complicated to observe local numeric constants when the program is noisy. Hence, we use
        the local strings as representatives of the alignment pattern for the numeric constants as well.
    """

    def __init__(self, analyzer):
        """Create the locals identifier instance.

        Args:
            analyzer (instance): analyzer instance that we are going to link against
        """
        self._local_alignment = None
        self._local_pad = None
        self._analyzer = analyzer

    def observeLocalConstants(self, scs):
        """Observe the alignment of local constants.

        Args:
            scs (list): list of (sark) code segments

        Note:
            We use the local strings as candidate to the numeric constants as well

        Return Value:
            The alignment pattern, as return for the alignment observer
        """
        # Singleton style
        if self._local_alignment is not None:
            return self._local_alignment, self._local_pad
        # Still didn't calculate the values
        self._analyzer.logger.info("Using strings as representatives to all in-code referred data constants")
        result = self._analyzer.str_identifier.observeLocalStrings(scs)
        if result is None:
            self._analyzer.logger.error("Failed to find more than one local constant, can't deduce any pattern...")
            return None
        # store and return the results
        self._local_alignment, self._local_pad = result
        return result

    def filterCRefs(self, line):
        """Filter the code refs for the given line, to remove "redundant" code references.

        Args:
            line (line): (sark) code line to be filtered

        Notes
        -----
            1. Code references from previous "alignment" lines will be dropped
            2. The rest of the code references are valid for now

        Return Value:
            generator of valid code references according to the filtering criteria
        """
        for cref in line.crefs_to:
            ref_line = sark.Line(cref)
            # if the alignment line before me is a "code", ignore it
            if ref_line.next == line and self._analyzer.isAlignment(ref_line):
                continue
            # this means it is a valid cref
            yield cref

    def isDataConstant(self, ea):
        """Check if the given address stores a local data constant (string / numeric).

        Args:
            ea (int): effective start address to be queried

        Notes
        -----
            1. Must have at least one data reference
            2. Must not have any effective code reference

        Return Value:
            True iff the given address matches the reference conditions of a local data constant
        """
        # line should be referenced (as data)
        return len(list(sark.Line(ea).drefs_to)) > 0 and len(list(self.filterCRefs(sark.Line(ea)))) == 0

    def locateLocalConstants(self, scs, sds):
        """Locate and define all of the local strings / numeric constants, that match our observed pattern.

        Args:
            scs (list): List of (sark) code segments.
            sds (list): List of (sark) data segments.
        """
        self._analyzer.logger.info("Locating local strings / constants in the code sections")
        for sc in scs:
            cur_ea = pad(sc.startEA, self._local_alignment)
            while cur_ea < sc.endEA:
                # check for a data constant
                if self.isDataConstant(cur_ea):
                    # check for a string (refs already checked)
                    if self._analyzer.str_identifier.isLocalAsciiString(cur_ea, check_refs=False):
                        length = self._analyzer.str_identifier.defineAsciiString(cur_ea)
                        padded_length = pad(length, self._local_alignment)
                        if padded_length != length:
                            idc.MakeUnknown(cur_ea + length, padded_length - length, 0)
                            idc.MakeData(cur_ea + length, 0, padded_length - length, 0)
                        cur_ea += padded_length
                    # This means it is a constant
                    else:
                        if self._local_pad is None:
                            idc.MakeData(cur_ea, 0, self._local_alignment, 0)
                        else:
                            # check the size of the constant using the byte padding
                            for offset in xrange(self._local_alignment - 1, -1, -1):
                                if idc.Byte(cur_ea + offset) != self._local_pad:
                                    break
                            # prepare the bytes
                            idc.MakeUnknown(cur_ea, self._local_alignment, 0)
                            # the data constant - try to make it pretty
                            if offset + 1 == 2:
                                idc.MakeWord(cur_ea)
                            elif offset + 1 == 4:
                                idc.MakeDword(cur_ea)
                            elif offset + 1 == 8:
                                idc.MakeQword(cur_ea)
                            else:
                                idc.MakeData(cur_ea, 0, offset + 1, 0)
                            # the padding
                            idc.MakeData(cur_ea + offset + 1, 0, self._local_alignment - offset + 1, 0)
                            # Now check for a pointer (only supports code pointers for now)
                            if offset + 1 == self._analyzer.addressSize():
                                value = self._analyzer.parseAdderss(cur_ea)
                                # only support pointers inside our local segment (more probable)
                                if sc.startEA <= value and value < sc.endEA:
                                    self._analyzer.markCodePtr(cur_ea, value, aggressive=False)
                                # try a pointer to a declared string
                                else:
                                    for sd in sds:
                                        if sd.startEA <= value and value <= sd.endEA:
                                            line = sark.Line(value)
                                            if line.is_string and line.startEA == value:
                                                self._analyzer.markDataPtr(cur_ea, value, aggressive=False)
                                            break
                        # now move onward
                        cur_ea += self._local_alignment
                # found nothing, move on
                else:
                    cur_ea += self._local_alignment
