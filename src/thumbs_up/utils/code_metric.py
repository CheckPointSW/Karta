import sark

class CodeMetric:
    """Class that collects and holds all code metrics for a given code range.

    Attributes
    ----------
        _analyzer (instance): analyzer instance to be used
        _start_ea (int): effective start address for the region's start
        _end_ea (int): effective end address for the region's start
        _unknown_count (int): total number of bytes in all unexplored code lines
        _illegal_count (int): total number of bytes in all illegal code instructions
        _contains_functions (bool): True iff the region contains a complete function
        _seen_function_start (int): effective start address of first function prologue that we saw
        _starting_function (function): (sark) function in which we started (None if didn't start in a function)
        _current_function  (function): (sark) function in which we are currently at (None if not inside a function)
        _containing_function (function): (sark) function in which we are contained, if there is one (None otherwise)
        _measure_align (bool): True iff should measure metrics for the region after the last code alignment
        _align_metric (CodeMetric): the inner alignment metric if exists (None otherwise)
        _align_start (bool): True iff just saw a code alignment
    """

    def __init__(self, analyzer, start_ea, measure_align=False):
        """Create a code metric instance for a given code region.

        Args:
            analyzer (instance): analyzer instance
            start_ea (int): effective start address for the region
            measure_align (bool, optional): True iff should measure metrics for the last aligned region too
        """
        self._analyzer = analyzer
        self._start_ea = start_ea
        self._end_ea   = None
        self._unknown_count = 0
        self._illegal_count = 0
        self._contains_functions  = False
        self._seen_function_start = -1
        self._starting_function   = None
        self._current_function    = None
        self._containing_function = None
        self._measure_align = measure_align
        self._align_metric  = None
        self._align_start   = False

    def start(self, line):
        """Start the measurement for the code region.

        Args:
            line (line): (sark) code line
        """
        try:
            self._starting_function = sark.Function(line.startEA)
        except Exception:
            self._starting_function = None
        # now record this line
        self.record(line)

    def record(self, line):
        """Record the given code / data line.

        Args:
            line (line): (sark) code line
        """
        is_illegal = not self._analyzer.isLegalInsn(line)
        self._unknown_count += line.size if line.is_unknown else 0
        self._illegal_count += line.size if is_illegal else 0
        # don't count functions that contain illegal instructions
        if (not is_illegal) and (not line.is_unknown):
            try:
                self._current_function = sark.Function(line.startEA)
                if line.startEA == self._current_function.startEA:
                    self._seen_function_start = line.startEA
                # Time to check if this is a contained function.
                # Note: could be one liner functions, so use "if" and not "elif"
                if line.endEA == self._current_function.endEA and self._current_function.startEA == self._seen_function_start:
                    self._contains_functions = True
            except Exception:
                self._current_function = None
        else:
            self._current_function = None
        # now check for an alignment
        if self._measure_align:
            if self._analyzer.isAlignment(line):
                self._align_start = True
            elif self._align_start:
                self._align_metric = CodeMetric(self._analyzer, line.startEA)
                self._align_metric.start(line)
                self._align_start = False
            elif self._align_metric is not None:
                self._align_metric.record(line)

    def stop(self, end_ea):
        """Stop the measurement of the current region.

        Args:
            end_ea (int): effective end address
        """
        self._end_ea = end_ea
        if self._starting_function is not None and self._current_function == self._starting_function:
            self._containing_function = self._starting_function
        # don't forget the alignment
        if self._align_metric is not None:
            self._align_metric.stop(end_ea)

    def borders(self):
        """Return the borders (start and end) of the region.

        Return Value:
            start ea, end ea
        """
        return self._start_ea, self._end_ea

    def unknowns(self):
        """Return the metric for the unknown (unexplored) bytes.

        Return Value:
            num of bytes in all unexplored lines, fraction of unexplored bytes
        """
        return self._unknown_count, 1.0 * self._unknown_count / (self._end_ea - self._start_ea)

    def illegals(self):
        """Return the metric for the illegal instructions.

        Return Value:
            num of bytes in all illegal instructions, fraction of illegal instruction bytes
        """
        return self._illegal_count, 1.0 * self._illegal_count / (self._end_ea - self._start_ea)

    def containsFunctions(self):
        """Return the status of contained functions.

        Return Value:
            True iff the region contains at least one full function
        """
        return self._contains_functions

    def containingFunction(self):
        """Return the containing function status (could be None).

        Return Value:
            containing function if exists (None otherwise)
        """
        return self._containing_function

    def startFunction(self):
        """Return the starting function status (could be None).

        Return Value:
            starting function if exists (None otherwise)
        """
        return self._starting_function

    def alignMetric(self):
        """Return the inner alignment metric.

        Return Value:
            the inner alignment code metric
        """
        return self._align_metric
