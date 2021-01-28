from .pattern_observer import pad
import idc
import ida_bytes
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

    def __init__(self, analyzer, local_alignment=None, local_pad=None):
        """Create the locals identifier instance.

        Args:
            analyzer (instance): analyzer instance that we are going to link against
            local_alignment (int, optional): local constant alignment (None by default)
            local_pad (int, optional): local constant alignment padding byte (None by default)
        """
        self._local_alignment = local_alignment
        self._local_pad = local_pad
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
            cur_ea = pad(sc.start_ea, self._local_alignment)
            while cur_ea < sc.end_ea:
                # Only interested in data constants
                if not self.isDataConstant(cur_ea):
                    cur_ea += self._local_alignment
                    continue
                # check for a string (refs already checked)
                if self._analyzer.str_identifier.isLocalAsciiString(cur_ea, check_refs=False):
                    length = self._analyzer.str_identifier.defineAsciiString(cur_ea)
                    padded_length = pad(length, self._local_alignment)
                    if padded_length != length:
                        ida_bytes.del_items(cur_ea + length, 0, padded_length - length)
                        ida_bytes.create_data(cur_ea + length, 0, padded_length - length, 0)
                    cur_ea += padded_length
                    continue
                # This means it is a constant, now check if we have a padding
                if self._local_pad is None:
                    ida_bytes.create_data(cur_ea, 0, self._local_alignment, 0)
                    cur_ea += self._local_alignment
                    continue
                # check the size of the constant using the byte padding
                for offset in range(self._local_alignment - 1, -1, -1):
                    if idc.get_wide_byte(cur_ea + offset) != self._local_pad:
                        break
                # prepare the bytes
                ida_bytes.del_items(cur_ea, 0, self._local_alignment)
                # the data constant - try to make it pretty
                if offset + 1 == 2:
                    ida_bytes.create_data(cur_ea, idc.FF_WORD, 2, idc.BADADDR)
                elif offset + 1 == 4:
                    ida_bytes.create_data(cur_ea, idc.FF_DWORD, 4, idc.BADADDR)
                elif offset + 1 == 8:
                    ida_bytes.create_data(cur_ea, idc.FF_QWORD, 8, idc.BADADDR)
                else:
                    ida_bytes.create_data(cur_ea, 0, offset + 1, 0)
                # the padding
                ida_bytes.create_data(cur_ea + offset + 1, 0, self._local_alignment - offset + 1, 0)
                # Now check for a pointer (only supports code pointers for now)
                if offset + 1 == self._analyzer.addressSize():
                    value = self._analyzer.parseAdderss(cur_ea)
                    # only support pointers inside our local segment (more probable)
                    if sc.start_ea <= value < sc.end_ea:
                        self._analyzer.markCodePtr(cur_ea, value, aggressive=False)
                    # try a pointer to a declared string
                    else:
                        for sd in sds:
                            if sd.start_ea <= value <= sd.end_ea:
                                line = sark.Line(value)
                                if line.is_string and line.start_ea == value:
                                    self._analyzer.markDataPtr(cur_ea, value, aggressive=False)
                                break
                # now move onward
                cur_ea += self._local_alignment
