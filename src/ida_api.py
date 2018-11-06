import idautils
import idaapi
import idc
import sark
import logging

######################
## Global Variables ##
######################

all_strings_singleton = None  # singleton list of all of the strings in the binary (heavy to calculate, so done once)
exported_singleton    = None  # singleton list of all of the exported entries

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

def idaGetString(ea):
    """Returns the string that was found on the given address, regardless of it's type

    Args:
        ea (int): effective address of the wanted string

    Return Value:
        A python string that contains the found string
    """
    str_type = idc.GetStringType(ea)
    if str_type is None:
        return None
    return idc.GetString(ea, -1, str_type)

def idaGetExported():
    """Returns a list of all of the exported symbols in the binary (singleton style)

    Return Value:
        list of all of the exported symbols in the *.idb
    """
    global exported_singleton

    # singleton
    if exported_singleton is None :
        exported_singleton = map(lambda x : x[-1], idautils.Entries())

    # return the result
    return exported_singleton

def renameIDAFunction(ea, name):
    """Renames the function at the specified address, using the supplied name
    
    Args:
        ea (int): effective address of the wanted function
        name (str): new name for the function
    """
    idc.MakeName(ea, name.encode("ascii"))
