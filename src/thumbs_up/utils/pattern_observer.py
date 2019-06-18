import idc
import random
import idautils

def gcd(x, y):
    """Find the Greatest Common Devisor (GCD) of the two given integers.

    Args:
        x (int): some integer
        y (int): another integer

    Return Value:
        The greatest common devisor of the two integers.
    """
    while(y):
        x, y = y, x % y
    return x

def padSize(raw_value, pad):
    """Calculate the needed padding size for the given value.

    Args:
        raw_value (int): raw value to be padded
        pad (int): padding that should be used

    Return Value:
        Number of padding bytes that should be used for the padding
    """
    return (pad - (raw_value % pad)) % pad

def pad(raw_value, pad):
    """Pad the given raw value, according to the given padding.

    Args:
        raw_value (int): raw value to be padded
        pad (int): padding to be used

    Return Value:
        Padded value
    """
    return raw_value + padSize(raw_value, pad)

class AlignmentPattern:
    """A class that extracts an alignment pattern from a set of given addresses (records).

    Attributes
    ----------
        _records (list): list of seen records (effective addresses)
    """

    def __init__(self):
        """Create and initialize an alignment pattern instance."""
        self._records = []

    def add(self, ea, size=None):
        """Add a record to the list of seen records.

        Args:
            ea (int): effective address which is the current record
            size (int, optional): size of the record (None by default)
        """
        self._records.append((ea, size))

    def size(self):
        """Return the number of observed records.

        Return Value:
            Number of seen records.
        """
        return len(self._records)

    def decide(self):
        """Sum up the information from all of the seen records, and decide what is the alignment pattern.

        Return Value:
            (alignment, pad byte) if found a full pattern, (alignment, None) if no padding, and None for errors.
        """
        # Sanity check
        if len(self._records) < 2:
            return None
        # Now check for a basic alignment rule
        seen_eas = map(lambda x: x[0], self._records)
        # Deterministic results per binary, but still random
        random.seed(int(idautils.GetInputFileMD5(), 16) & 0xFFFFFFFF)
        while True:
            # Check against two random candidates, and always make sure the representative isn't rare
            measure_candidate = seen_eas[random.randint(0, len(seen_eas) - 1)]
            measure_candidate_alt = seen_eas[random.randint(0, len(seen_eas) - 1)]
            gcds = map(lambda x: gcd(measure_candidate, x), seen_eas)
            gcds_alt = map(lambda x: gcd(measure_candidate_alt, x), seen_eas)
            alignment = min(gcds)
            alignment_alt = min(gcds_alt)
            if alignment > alignment_alt:
                alignment = alignment_alt
                measure_candidate = measure_candidate_alt
                try_again = True
            elif alignment != alignment_alt:
                try_again = True
            else:
                try_again = False
            # Try to check if removing outliers will improve the alignment
            if try_again or gcds.count(alignment) <= len(gcds) * 0.01:
                # pick the next element, and try to improve the result
                seen_eas = filter(lambda x: gcd(measure_candidate, x) != alignment, seen_eas)
            # we can't improve the results
            else:
                break
        # We shouldn't look for padding bytes (we have no size)
        if self._records[0][1] is None:
            return alignment
        # Alignment is 1, there is no padding to be found
        if alignment == 1:
            return (alignment, None)
        # Check if there is a common padding byte (skip the outliers)
        pad_byte = None
        for ea, size in filter(lambda x: x[0] % alignment == 0, self._records):
            for offset in xrange((alignment - ((ea + size) % alignment)) % alignment):
                test_byte = idc.Byte(ea + size + offset)
                if pad_byte is None:
                    pad_byte = test_byte
                # Failed to find a single padding byte...
                elif pad_byte != test_byte:
                    return (alignment, None)
        # Found a padding byte :)
        if pad_byte is not None:
            return (alignment, pad_byte)
        # There were no gaps to be padded, no padding is needed
        else:
            return (alignment, None)

class CodePattern:
    """A class that extracts an assembly code pattern from a set of given assembly instructions.

    Attributes
    ----------
        _records (list): list of seen records of the form: (string mnemonic, [string operands, ])
        _instr (string): the chosen assembly instruction pattern (if one was chosen)
        _operands (dict): mapping of chosen instruction operands: index => string value
    """

    def __init__(self):
        """Create and initialize a code pattern instance."""
        self._records  = []
        self._instr    = None
        self._operands = {}

    def add(self, instr):
        """Add a record to the list of seen records.

        Args:
            instr (line): (sark) code line

        Note:
            The record features are extracted from the given code line
        """
        self._records.append((instr.insn.mnem, map(str, instr.insn.operands)))

    def size(self):
        """Return the number of observed records.

        Return Value:
            Number of seen records.
        """
        return len(self._records)

    def query(self, instr):
        """Query the stored state, and check if the given instruction matches the pattern.

        Args:
            instr (line): (sark) code line

        Return Value:
            True iff the given line matches the stored pattern
        """
        # should be checked earlier by the caller (return value of decide())
        if self._instr is None:
            return False
        # check the instruction
        if self._instr != instr.insn.mnem:
            return False
        # check the number of mandatory operands
        if max(self._operands.keys()) >= len(instr.insn.operands):
            return False
        # check the mandatory operands themselves
        for ind, value in self._operands.items():
            if value != str(instr.insn.operands[ind]):
                return False
        # All was Ok if reached thus far
        return True

    def decide(self):
        """Sum up the information from all of the seen records, and decide what is the code pattern.

        Note:
            The decision will be stored in the instance's internal state, and will be used by the query()
            method.

        Return Value:
            True iff found a code pattern
        """
        # Sanity check
        if len(self._records) < 2:
            return False
        # Now check for the same instruction
        seen_instr = self._records[0][0]
        for record in self._records[1:]:
            if seen_instr != record[0]:
                seen_instr = None
                break
        # Failed to find a common command
        if seen_instr is None:
            return False
        self._instr = seen_instr
        # Now try to check for common operands
        if len(self._records[0][1]) == 0:
            return True
        self._operands = {}
        for i in xrange(len(self._records[0][1])):
            self._operands[i] = self._records[0][1][i]
        # now gradually narrow them down
        for record in self._records[1:]:
            dropped = []
            for ind, value in self._operands.items():
                if ind >= len(record[1]):
                    dropped.append(ind)
                    continue
                if value != record[1][ind]:
                    dropped.append(ind)
                    continue
            for ind in dropped:
                self._operands.pop(ind)
            if len(self._operands) == 0:
                break
        # Failed to find any common operand
        if len(self._operands) == 0:
            return False
        # Found several (at least one) common operands :)
        return True

    def __str__(self):
        """Nicely represent the matched code pattern as a string.

        Return Value:
            String representation of the code pattern
        """
        values = []
        if len(self._operands) > 0:
            for ind in xrange(max(self._operands.keys()) + 1):
                values.append(self._operands[ind] if ind in self._operands else "_")
        return self._instr + " " + ", ".join(values)
