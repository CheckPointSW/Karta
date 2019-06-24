import idc
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
classifier_type_offsets   = range(0, 8)         # Code type classifier - used for identifying the code type of a given blob, possibly after a transition

class ArmAnalyzer(Analyzer):
    """ARM-based program analyzer."""

    def __init__(self, logger, num_bits):
        """Create the Arm Analyzer instance.

        Args:
            logger (logger): logger instance
            num_bits (int): bitness of the CPU (32 bits by default)
        """
        Analyzer.__init__(self, logger, num_bits, data_fptr_alignment=(4 if num_bits <= 32 else 8))

    # Overridden base function
    def linkFunctionClassifier(self):
        """Link a function classifier to our analyzer."""
        self.func_classifier = FunctionClassifier(self, function_feature_size, function_inner_offset, classifiers_start_offsets, classifiers_end_offsets, classifiers_mixed_offsets, classifier_type_offsets)

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
    def isCodeContainsData(self):
        """Check if the code might contain data constants.

        Notes
        -----
            False by default (for most architectures)
        """
        return True

    # Overridden base function
    def isCodeAligned(self, ea, code_type=None):
        """Check if the code is aligned according to the given code type.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the code address is aligned correctly
        """
        if code_type is None:
            code_type = self.codeType(ea)
        return ea % (2 if code_type else 4) == 0

    # Overridden base function
    def isCodeTransitionAligned(self, ea, code_type=None):
        """Check if the transition between code types is aligned correctly.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the transition address is aligned correctly
        """
        # Even Thumb gaps should start aligned to 4
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
        # Even Thumb gap should start aligned to 4
        return ea - (ea % 4)

    # Overridden base function
    def cleanPtr(self, ptr_ea):
        """Clean a pointer from the code type metadata.

        Args:
            ptr_ea (int): code type annotated effective address

        Return Value:
            dest address, stripped from the code type annotations
        """
        return ptr_ea - ptr_ea % 2

    # Overridden base function
    def annotatePtr(self, ea, code_type):
        """Annotate a pointer to include the code type metadata.

        Args:
            ea (int): clean effective address
            code_type (int): code type to be encoded in the annotation

        Return Value:
            dest address, annotated with the code type
        """
        return ea + code_type

    # Overridden base function
    def hasCodeTypes(self):
        """Check if the given CPU has multiple code types.

        Return Value:
            True iff CPU supports multiple code types
        """
        return True

    # Overridden base function
    def codeTypes(self):
        """Return a tuple of the CPU supported code types.

        Return Value:
            collection of supported code types
        """
        return 0, 1

    # Overridden base function
    def ptrCodeType(self, ptr_ea):
        """Extract the code type of the annotated pointer.

        Args:
            ptr_ea (int): annotated effective address

        Return Value:
            The code type of the annotated pointer
        """
        return ptr_ea % 2

    # Overridden base function
    def codeType(self, ea):
        """Query IDA for the code type at the given address.

        Args:
            ea (int): effective code address

        Return Value:
            The current code type at the given address
        """
        return idc.GetReg(ea, 'T')

    # Overridden base function
    def setCodeType(self, ea_start, ea_end, code_type):
        """Set the code type for the given address range.

        Args:
            ea_start (int): effective address for the start of the range
            ea_end (int): effective address for the end of the range
            code_type (int): wanted code type for the code range
        """
        for offset in xrange(ea_end - ea_start):
            idc.SetReg(ea_start + offset, 'T', code_type)

    # Overridden base function
    def isLegalInsn(self, line):
        """Check if the given code line represents a legal instruction.

        Args:
            line (sark line): sark code line

        Return Value:
            True iff all supported heuristics show the instruction is legal
        """
        str_line = str(line)
        if '+' in str_line:
            last_part = str_line.split('+')[-1]
            try:
                if int(last_part) > 1:
                    return False
            except ValueError:
                pass
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
        return is_align or (line.is_code and line.insn.mnem == "NOP")


# Register our analyzer at the factory
registerAnalyzer("ARMB", ArmAnalyzer)
registerAnalyzer("ARM",  ArmAnalyzer)
