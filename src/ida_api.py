import idautils
import idaapi
import idc
import sark
import logging

######################
## Global Variables ##
######################

all_strings_singleton = None  # singleton list of all of the strings in the binary (heavy to calculate, so done once)

class IdaLogHandler(logging.Handler) :
    """Integrates the log messages with IDA's output window"""
    def emit(self, record) :
        idc.Message("%s\n" % (super(IdaLogHandler, self).format(record)))

def idaStringList():
    """Returns a list of all of the string in the binary (singleton style)

    Return Value:
        list of all of the used strings in the *.idb
    """
    global all_strings_singleton

    # singleton
    if all_strings_singleton is None :
        all_strings_singleton = list(idautils.Strings())

    # return the result
    return all_strings_singleton

def renameIDAFunction(ea, name):
    """Renames the function at the specified address, using the supplied name
    
    Args:
        ea (int): effective address of the wanted function
        name (str): new name for the function
    """
    idc.MakeName(ea, name.encode("ascii"))
