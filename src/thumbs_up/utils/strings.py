from .pattern_observer import AlignmentPattern, pad, padSize
import idc
import idautils
import idaapi
import string
import sark

#######################
## String Heuristics ##
#######################

# Probable Alpha-Bet for ascii strings
valid_ascii_string_chars = filter(lambda x: x not in "\x0B\x0C", string.printable) + "\x1B"
# Minimal string length for global strings (Going to be on the Safe Side)
minimal_string_length = 6

class StringIdentifier:
    """A class that collects the information and holds the knowledge we know about local and global strings in the program.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _min_global_length (int): minimal length of an ascii strings that will be located in the globals (Data segments)
        _valid_alphabet (string): set of ascii chars that holds the entire legal alphabet for all of our ascii strings
        _local_alignment (int): byte alignment for the "local" strings - strings that appear in code segments
        _local_pad (int): numeric value of the padding byte of local strings, if one exists (None otherwise)
        _global_alignment (int): byte alignment for the "global" strings - strings that appear in data segments
        _global_pad (int): numeric value of the padding byte of global strings, if one exists (None otherwise)

    Notes
    -----
        1. Deriving the alignment of global strings appears to be quite noisy. At the current moment we assume that
           it will be the same as in the local case.
        2. We use different heuristics for detecting global and local strings, as we allow ourselves more freedom in the
           local case, in which we have more strict requirements for declaring a string in the first place.
    """

    def __init__(self, analyzer, minimal_globals_length=minimal_string_length, ascii_alphabet=valid_ascii_string_chars):
        """Create a basic string identifier that will be used by the supplied analyzer.

        Args:
            analyzer (instance): analyzer instance that we will link to
            minimal_globals_length (int): minimum length threshold for global strings
            ascii_alphabet (string): set of ascii chars that will define the valid dictionary (alpha-bet) for all the strings
        """
        self._min_global_length  = minimal_globals_length
        self._valid_alphabet     = ascii_alphabet
        # must start with 1 to allow basic scanners to search for strings
        self._local_alignment    = 1
        self._local_pad          = None
        self._global_alignment   = 1
        self._global_pad         = None
        self._analyzer           = analyzer

    def setLocalAlignment(self, alignment, pad=0):
        """Define the local alignment characteristics.

        Args:
            alignment (int): byte alignment that should be used for the local strings
            pad (int, optional): padding byte value to be used when alignment > 1 (0 by default)
        """
        self._local_alignment = alignment
        self._local_pad = pad

    def setGlobalAlignment(self, alignment, pad=0):
        """Define the global alignment characteristics.

        Args:
            alignment (int): byte alignment that should be used for the global strings
            pad (int, optional): padding byte value to be used when alignment > 1 (0 by default)
        """
        self._global_alignment = alignment
        self._global_pad = pad

    def getAsciiString(self, ea):
        """Fetch the best ascii string that starts at the given address, according to IDA.

        Args:
            ea (int): effective address of the wanted string

        Return Value:
            IDA's best ascii string that starts at the given address
        """
        return idc.GetString(ea, -1, -1)

    def isGlobalAsciiString(self, ea):
        r"""Check if the given address is the beginning of a valid global string.

        Args:
            ea (int): effective address to be checked

        Notes
        -----
            1. The string should be aligned (global alignment).
            2. The string should only contain chars from our alpha-bet.
            3. The string should be '\0' terminated.
            4. If applicable, the string should be padded with the correct padding byte.
            5. The string's length must be at least the required lower bound.

        Return Value:
            True iff the given address could be the start of a global string
        """
        # start by checking the alignment
        if ea % self._global_alignment != 0:
            return False
        str_content = self.getAsciiString(ea)
        # check each of the chars
        if str_content is None or len(filter(lambda x: x in self._valid_alphabet, str_content)) != len(str_content):
            return False
        # check for a '\0' terminator
        if idc.Byte(ea + len(str_content)) != ord('\0'):
            return False
        # check for the correct padding
        end_address = ea + len(str_content) + 1
        if self._global_pad is not None:
            for offset in xrange(padSize(end_address, self._global_alignment)):
                if idc.Byte(end_address + offset) != self._global_pad:
                    return False
        # basic length
        return len(str_content) >= self._min_global_length

    def isLocalAsciiString(self, ea, check_refs=True):
        r"""Check if the given address is the beginning of a valid local string.

        Args:
            ea (int): effective address to be checked

        Notes
        -----
            0. If selected, the string must have a data reference to it.
            1. The string should be aligned (local alignment).
            2. The string should only contain chars from our alpha-bet.
            3. The string should be '\0' terminated.
            4. If applicable, the string should be padded with the correct padding byte.
            5. The string's length must follow one of the following rules:
                a) Larger than the local alignment.
                b) At least 2 bytes, and the first is '%' (for short format strings).
                c) Exactly one byte, and it should be a punctuation char.
                d) At least 3 bytes.

        Return Value:
            True iff the given address could be the start of a local string
        """
        # line should be referenced (as data)
        if check_refs and not self._analyzer.locals_identifier.isDataConstant(ea):
            return False
        str_content = self.getAsciiString(ea)
        # check each of the chars
        if str_content is None or len(filter(lambda x: x in self._valid_alphabet, str_content)) != len(str_content):
            return False
        # check for a '\0' terminator
        if idc.Byte(ea + len(str_content)) != ord('\0'):
            return False
        # check for the correct padding
        end_address = ea + len(str_content) + 1
        if self._local_pad is not None:
            for offset in xrange(padSize(end_address, self._local_alignment)):
                if idc.Byte(end_address + offset) != self._local_pad:
                    return False
        # filtering heuristic
        if len(str_content) > self._local_alignment:
            return True
        elif len(str_content) > 1 and str_content[0] == '%':
            return True
        elif len(str_content) == 1 and str_content[0] in string.punctuation:
            return True
        else:
            return len(str_content) > 2

    # TODO: unused for now
    def observerGlobalStrings(self, sds):
        """Observe and (hopefully) detect a pattern in all of the global strings.

        Args:
            sds (list): List of (sark) Data segments.
        """
        pattern = AlignmentPattern()
        for sd in sds:
            self._analzyer.logger.debug("Data Segment: 0x%x - 0x%x", sd.startEA, sd.endEA)
        # collect the data from all of the global strings
        for cur_string in idautils.Strings():
            string_ea = cur_string.ea
            for sd in sds:
                if sd.startEA <= string_ea and string_ea < sd.endEA:
                    if self.isGlobalAsciiString(string_ea):
                        pattern.add(string_ea, len(self.getAsciiString(string_ea)))
                    break
        # find the pattern
        result = pattern.decide()
        # set out features accordingly
        if result is not None:
            self.setGlobalAlignment(result[0], result[1])

    def locateDataStrings(self, sds):
        """Locate and define all of the global strings that match our observed pattern.

        Args:
            sds (list): List of (sark) Data segments.
        """
        for sd in sds:
            self._analyzer.logger.info("Locating global strings in the data segment: 0x%x - 0x%x", sd.startEA, sd.endEA)
            cur_ea = pad(sd.startEA, self._global_alignment)
            while cur_ea < sd.endEA:
                # check for a string
                if self.isGlobalAsciiString(cur_ea):
                    length = self.defineAsciiString(cur_ea)
                    cur_ea += pad(length, self._global_alignment)
                else:
                    cur_ea = self.nextGlobalString(cur_ea)

    def nextGlobalString(self, ea):
        """Find the next possible address for a global string, given the beginning of the current global string.

        Args:
            ea (int): effective start address of the current global string.

        Return Value:
            Possible start address for the next global string
        """
        str_content = self.getAsciiString(ea)
        if str_content is None:
            return ea + self._global_alignment
        elif idc.Byte(ea + len(str_content)) != ord('\0'):
            return ea + max(self._global_alignment, pad(len(str_content), self._global_alignment))
        else:
            for offset in xrange(len(str_content) - 1, -1, -1):
                if str_content[offset] not in string.printable:
                    return ea + max(self._global_alignment, pad(offset, self._global_alignment))
        return ea + self._global_alignment

    def observeLocalStrings(self, scs):
        """Observe and (hopefully) detect a pattern in all of the local strings.

        Args:
            scs (list): List of (sark) Code segments.

        Return Value:
            (alignment, pad) as was returned from the alignment pattern observer
        """
        pattern = AlignmentPattern()
        for sc in scs:
            # collect the data
            for line in sc.lines:
                if line.is_string and self.isLocalAsciiString(line.startEA):
                    pattern.add(line.startEA, len(line.bytes))
        # find the pattern
        alignment, pad = pattern.decide()
        self._analyzer.logger.info("String byte alignment is: %d", alignment)
        if alignment > 1 and pad is not None:
            self._analyzer.logger.info("String byte alignment padding value is: %d", pad)
        self.setLocalAlignment(alignment, pad)
        # Currently using the local alignment for the globals as well, as was described at the start of the class.
        self.setGlobalAlignment(alignment, pad)
        return alignment, pad

    def defineAsciiString(self, ea):
        r"""Define an ascii string at the given address.

        Args:
            ea (int): effective start address of the wanted ascii string

        Return Value:
            The length of the defined string + 1 for the '\0' terminator
        """
        content = idc.GetString(ea, -1, -1)
        if not sark.Line(ea).is_string:
            self._analyzer.logger.debug("Defined a unique ascii string at: 0x%x (Length of %d)", ea, len(content) + 1)
        idc.MakeUnknown(ea, len(content) + 1, 0)
        # Backward compatibility is always fun
        if idaapi.IDA_SDK_VERSION <= 700:
            idaapi.make_ascii_string(ea, len(content) + 1, idc.ASCSTR_C)
        else:
            idc.MakeStr(ea, ea + len(content) + 1)
        return len(content) + 1
