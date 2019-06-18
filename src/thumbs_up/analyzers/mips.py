from .analyzer              import Analyzer
from .analyzer_factory      import registerAnalyzer
from utils.function         import FunctionClassifier
from utils.strings          import StringIdentifier
from utils.local_constants  import LocalsIdentifier
from utils.fptr             import FptrIdentifier
from utils.switch_table     import SwitchIdentifier

###############################
# Architecture Configurations #
###############################

function_feature_size     = 6                   # This is the number of features that will be used after we calibrate the classifier
function_inner_offset     = 64                  # Offset in bytes into what we hope is a middle of our function

# These are the byte offsets we are going to use for calibrating the classifier, before picking the final offsets
classifiers_start_offsets = {                   # Start of function classifier - used for functions after a code transition
                             0: range(0, 12),
                             1: range(0, 12),
                            }
classifiers_end_offsets   = {                   # End of function classifier - used for functions before a code transition
                             0: range(-12, 0),
                             1: range(-12, 0),
                            }
classifiers_mixed_offsets = {                   # Start / End function classifier - used for start of functions when we don't fear code transitions
                             0: range(-4, 12),
                             1: range(-4, 12),
                            }

class MipsAnalyzer(Analyzer):
    """MIPS-based program analyzer."""

    def __init__(self, logger, num_bits):
        """Create the MIPS Analyzer instance.

        Args:
            logger (logger): logger instance
            num_bits (int): bitness of the CPU (32 bits by default)
        """
        Analyzer.__init__(self, logger, num_bits, data_fptr_alignment=(4 if num_bits <= 32 else 8))

    # Overridden base function
    def linkFunctionClassifier(self):
        """Link a function classifier to our analyzer."""
        self.func_classifier = FunctionClassifier(self, function_feature_size, function_inner_offset, classifiers_start_offsets, classifiers_end_offsets, classifiers_mixed_offsets, None)

    # Overridden base function
    def linkFptrIdentifier(self):
        """Link a fptr identifier to our analyzer."""
        self.fptr_identifier = FptrIdentifier(self)

    # Overridden base function
    def linkStringIdentifier(self):
        """Link a string identifier to our analyzer."""
        self.str_identifier = StringIdentifier(self)

    # Overridden base function
    def linkLocalsIdentifier(self):
        """Link a local constants identifier to our analyzer."""
        self.locals_identifier = LocalsIdentifier(self)

    # Overridden base function
    def linkSwitchIdentifier(self):
        """Link a switch tables identifier to our analyzer."""
        self.switch_identifier = SwitchIdentifier(self)

    # Overridden base function
    def isCodeAligned(self, ea, code_type=None):
        """Check if the code is aligned according to the given code type.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the code address is aligned correctly
        """
        return ea % 4 == 0

    # Overridden base function
    def isCodeTransitionAligned(self, ea, code_type=None):
        """Check if the transition between code types is aligned correctly.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the transition address is aligned correctly
        """
        return ea % 4 == 0

    # Overridden base function
    def alignTransitionAddress(self, ea, code_type):
        """Align *down* the code address of the transition, according to the given code type.

        Args:
            ea (int): effective code address to be aligned
            code_type (int): known code type for the alignment

        Return Value:
            Aligned code address, which is: aligned address <= original address
        """
        return ea - (ea % 4)

    # Overridden base function
    def isLegalInsn(self, line):
        """Check if the given code line represents a legal instruction.

        Args:
            line (sark line): sark code line

        Return Value:
            True iff all supported heuristics show the instruction is legal
        """
        # TODO: maybe implement in the future
        return True

    # Overridden base function
    def isAlignment(self, line):
        """Check if the given code line represents a code alignment.

        Args:
            line (sark line): sark code line

        Return Value:
            True iff the code line represents a code alignment
        """
        is_align = Analyzer.isAlignment(self, line)
        return is_align or (line.is_data and not line.is_string and ".align " in str(line))


# Register our analyzer at the factory
registerAnalyzer("mipsb", MipsAnalyzer)
registerAnalyzer("mipsl", MipsAnalyzer)
