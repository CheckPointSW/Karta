from idc import *
from idaapi import *
from idautils import *

import logging

######################
## Global Variables ##
######################

all_bin_string = None  # singleton list of all of the strings in the binary (heavy to calculate, so done once)

IDA_KERNEL_VERSION = get_kernel_version()

class IdaLogHandler(logging.Handler) :
    """Integrates the log messages with IDA's output window"""
    def emit(self, record) :
        Message("%s\n" % (super(IdaLogHandler, self).format(record)))
        
def decodeInstruction(ea) :
    """Backward-compatible way to decode an instruction from it's effective address

    Args:
        ea (int): effective address of the wanted instruction

    Return Value:
        (instruction size, instruction (insn_t instance))
    """
    global IDA_KERNEL_VERSION
    if IDA_KERNEL_VERSION.startswith("7.") :
        ins = insn_t()
        # on version 7+ 'ins' is an our parameter of 'decode_insn()'
        size = decode_insn(ins, ea)
        return size, ins
    elif IDA_KERNEL_VERSION.startswith("6.") :
        size = decode_insn(ea)
        # idautils (idapython 6.7) recommends to copy the created 'cmd' (insnt_t) instance
        return size, cmd.copy()
    else :
        raise Exception("Unsupported IDA kernel version! found in decodeInstruction()")

def isDataRef(oper, ea) :
    """Checks if the given operation refers to the Data section
    
    Args:
        oper (IDA.oper): operation to be checked
        ea (int): effective address of the given operation

    Return Value:
        True iff the operation is in fact a reference to the Data section
    """
    return oper.value in DataRefsFrom(ea)

def stringList():
    """Returns a list of all of the string in the binary (singleton style)

    Return Value:
        list of all of the used strings in the *.idb
    """
    global all_bin_string

    # singleton
    if all_bin_string is None :
        all_bin_string = list(Strings())

    # return the result
    return all_bin_string
