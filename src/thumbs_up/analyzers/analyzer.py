import idc
import ida_bytes
import ida_offset

class Analyzer:
    """A base class representing our CPU-based knowledge.

    Attributes
    ----------
        logger (logger): logger instance
        func_classifier (instance): function classifier instance
        fptr_identifier (instance): function pointer identifier instance
        str_identifier (instance): string identifier instance
        locals_identifier (instance): local constants identifier instance
        switch_identifier (instance): switch tables identifier instance
        _num_bits (int): the bitness of the CPU
        _is_elf (bool): True iff analyzing an ELF binary
        data_fptr_alignment (int): the basic alignment in which data fptrs are stored
        _mixed_code_and_data (bool): True iff the main code section contain RO data globals
        _address_parse_fn (function): IDA function for parsing an address, stored for efficiency
        _address_make_fn (function): IDA function for serializing an address, stored for efficiency
        address_pack_format (string): struct.pack format letter for packing an address, stored efficiently
        _active_code_types (list): collection of active code types (supported & existings)
    """

    def __init__(self, logger, num_bits, is_elf, data_fptr_alignment=4, mixed_code_and_data=False):
        """Create the analyzer's base class instance.

        Args:
            logger (logger): logger instance
            num_bits (int): bitness of the CPU (32 bits by default)
            data_fptr_alignment (int, optional): byte alignment needed for global fptrs (4 by default)
            mixed_code_and_data (bool, optional): True iff the main code section includes RO data constants (False by default)
        """
        self.logger = logger
        self._num_bits = num_bits
        self._is_elf = is_elf
        self.data_fptr_alignment = data_fptr_alignment
        self._mixed_code_and_data = mixed_code_and_data
        if num_bits == 64:
            self._address_parse_fn = idc.get_qword
            self._address_make_fn = lambda x: ida_bytes.create_data(x, idc.FF_QWORD, 8, idc.BADADDR)
            self.address_pack_format = "Q"
        elif num_bits == 32:
            self._address_parse_fn = idc.get_wide_dword
            self._address_make_fn = lambda x: ida_bytes.create_data(x, idc.FF_DWORD, 4, idc.BADADDR)
            self.address_pack_format = "L"
        else:
            self._address_parse_fn = idc.get_wide_word
            self._address_make_fn = lambda x: ida_bytes.create_data(x, idc.FF_WORD, 2, idc.BADADDR)
            self.address_pack_format = "H"
        # fields to be linked later on
        self.func_classifier = None
        self.fptr_identifier = None
        self.str_identifier = None
        self.locals_identifier = None
        self.switch_identifier = None
        # code types
        self._active_code_types = list(self.codeTypes())

    def linkFunctionClassifier(self):
        """Link a function classifier to our analyzer."""
        raise NotImplementedError("Subclasses should implement this!")

    def linkFptrIdentifier(self):
        """Link a fptr identifier to our analyzer."""
        raise NotImplementedError("Subclasses should implement this!")

    def linkStringIdentifier(self):
        """Link a string identifier to our analyzer."""
        raise NotImplementedError("Subclasses should implement this!")

    def linkLocalsIdentifier(self):
        """Link a local constants identifier to our analyzer."""
        raise NotImplementedError("Subclasses should implement this!")

    def linkSwitchIdentifier(self):
        """Link a switch tables identifier to our analyzer."""
        raise NotImplementedError("Subclasses should implement this!")

    def presentCodeTypes(self):
        """Print a list of the supported code types."""
        raise NotImplementedError("Subclasses should implement this!")

    def addressSize(self):
        """Address size in bytes, according to the CPU's bitness.

        Return Value:
            Number of bytes in an address (The CPU's "Word" size)
        """
        return self._num_bits // 8

    def parseAdderss(self, ea):
        """Parse the stored address from it's byte representation.

        Args:
            ea (int): effective address in which the address is stored

        Return Value:
            Numeric address as is stored in the given address
        """
        return self._address_parse_fn(ea)

    def makeAddress(self, ea):
        """Serialize an address to be stored at it's byte representation.

        Args:
            ea (int): effective address in which the address should be stored

        Return Value:
            result of the idc.MakeX for the appropriate address type
        """
        return self._address_make_fn(ea)

    def isCodeContainsData(self):
        """Check if the code might contain data constants.

        Notes
        -----
            False by default (for most architectures)

        Return Value:
            True iff data immediates will be douns in the code section (between functions)
        """
        return False

    def isCodeMixedWithData(self):
        """Check if the code contains Read-Only data constants.

        Notes
        -----
            False by default (for most architectures)

        Return Value:
            True iff Read-Only data constants will be contained in the text section
        """
        return self._mixed_code_and_data

    def isCodeAligned(self, ea, code_type=None):
        """Check if the code is aligned according to the given code type.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the code address is aligned correctly
        """
        raise NotImplementedError("Subclasses should implement this!")

    def isCodeTransitionAligned(self, ea, code_type=None):
        """Check if the transition between code types is aligned correctly.

        Args:
            ea (int): effective address of the code to be checked
            code_type (int, optional): known code type for the given address (None by default)

        Return Value:
            True iff the transition address is aligned correctly
        """
        raise NotImplementedError("Subclasses should implement this!")

    def alignTransitionAddress(self, ea, code_type):
        """Align *down* the code address of the transition, according to the given code type.

        Args:
            ea (int): effective code address to be aligned
            code_type (int): known code type for the alignment

        Return Value:
            Aligned code address, which is: aligned address <= original address
        """
        raise NotImplementedError("Subclasses should implement this!")

    def markCodePtr(self, src, dest, aggressive=True):
        """Mark a code pointer from src to dest.

        Args:
            src (int): effective address for the pointer's location
            dest (int): effective address for the pointed code address
            aggressive (bool, optional): True iff should redefine the src & dest (True by default)
        """
        clean_dest = self.cleanPtr(dest)
        if aggressive:
            ida_bytes.del_items(src, 0, self.addressSize())
        if self.makeAddress(src):
            idc.add_dref(src, clean_dest, idc.XREF_USER | idc.dr_O)
            idc.add_cref(src, clean_dest, idc.XREF_USER | idc.dr_O)
            ida_offset.op_offset(src, 0, idc.REF_OFF32)
            if aggressive:
                ida_bytes.del_items(dest, 0, self.addressSize())
                idc.create_insn(self.cleanPtr(dest))

    def markDataPtr(self, src, dest, aggressive=True):
        """Mark a data pointer from src to dest.

        Args:
            src (int): effective address for the pointer's location
            dest (int): effective address for the pointed data address
            aggressive (bool, optional): True iff should redefine the src (True by default)
        """
        if aggressive:
            ida_bytes.del_items(src, 0, self.addressSize())
        if self.makeAddress(src):
            idc.add_dref(src, dest, idc.XREF_USER | idc.dr_O)
            ida_offset.op_offset(src, 0, idc.REF_OFF32)

    def delCodePtr(self, src, dest):
        """Delete a code pointer (probably was found to be a False Positive).

        Args:
            src (int) effective address for the pointer's location
            dest (int): effective address for the (assumed) pointed code address
        """
        idc.del_dref(src, dest)
        idc.del_cref(src, dest, 0)
        ida_bytes.del_items(src, 0, self.addressSize())

    def cleanPtr(self, ptr_ea):
        """Clean a pointer from the code type metadata.

        Args:
            ptr_ea (int): code type annotated effective address

        Return Value:
            dest address, stripped from the code type annotations
        """
        # By default, there is only the default code type
        return ptr_ea

    def annotatePtr(self, ea, code_type):
        """Annotate a pointer to include the code type metadata.

        Args:
            ea (int): clean effective address
            code_type (int): code type to be encoded in the annotation

        Return Value:
            dest address, annotated with the code type
        """
        # By default, there is only the default code type
        return ea

    def isValidCodePtr(self, ptr_ea):
        """Check if the given code pointer matches it's code type annotations.

        Args:
            ptr_ea (int): annotated effective address

        Return Value:
            True iff the code pointer is valid
        """
        ptr_type = self.ptrCodeType(ptr_ea)
        return self.isCodeAligned(self.cleanPtr(ptr_ea), ptr_type) and self.supportedCodeType(ptr_type)

    def hasCodeTypes(self):
        """Check if the given CPU has multiple code types.

        Return Value:
            True iff CPU supports multiple code types
        """
        # By default, there is only the default code type
        return False

    def hasActiveCodeTypes(self):
        """Check if the given CPU has multiple *active* code types.

        Return Value:
            True iff the CPU, and our binary, supports multiple code types
        """
        return self.hasCodeTypes() and len(self.activeCodeTypes()) > 1

    def codeTypes(self):
        """Return a tuple of the CPU supported code types.

        Return Value:
            collection of supported code types
        """
        # By default, there is only the default code type
        return (0,)

    def activeCodeTypes(self):
        """Return a tuple of the CPU supported code types there we found in the binary.

        Return Value:
            collection of supported & existing code types
        """
        return self._active_code_types

    def disableCodeType(self, code_type):
        """Mark a given code type as "disabled" - we didn't see it in our binary.

        Args:
            code_type (int): code type to be disabled
        """
        if self.supportedCodeType(code_type):
            self._active_code_types.remove(code_type)

    def supportedCodeType(self, code_type):
        """Check if a given code_type is actively supported.

        Args:
            code_type (int): code type to be checked

        Return Value:
            The code type of the annotated pointer
        """
        return code_type in self._active_code_types

    def ptrCodeType(self, ptr_ea):
        """Extract the code type of the annotated pointer.

        Args:
            ptr_ea (int): annotated effective address

        Return Value:
            The code type of the annotated pointer
        """
        # By default, there is only the default code type
        return 0

    def codeType(self, ea):
        """Query IDA for the code type at the given address.

        Args:
            ea (int): effective code address

        Return Value:
            The current code type at the given address
        """
        # By default, there is only the default code type
        return 0

    def setCodeType(self, ea_start, ea_end, code_type):
        """Set the code type for the given address range.

        Args:
            ea_start (int): effective address for the start of the range
            ea_end (int): effective address for the end of the range
            code_type (int): wanted code type for the code range
        """
        # By default, there is only the default code type
        pass

    def isLegalInsn(self, line):
        """Check if the given code line represents a legal instruction.

        Args:
            line (sark line): sark code line

        Return Value:
            True iff all supported heuristics show the instruction is legal
        """
        raise NotImplementedError("Subclasses should implement this!")

    def isAlignment(self, line):
        """Check if the given code line represents a code alignment.

        Args:
            line (sark line): sark code line

        Return Value:
            True iff the code line represents a code alignment
        """
        return " align " in str(line).lower()
