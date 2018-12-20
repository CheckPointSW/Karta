import collections

######################
## Global Variables ##
######################

libraries_factory   = collections.OrderedDict()        # Mapping from library name => init function for the library plugin

def registerLibrary(name, init_fn):
    """Register the library in the overall factory.

    Args:
        name (str): name of the open source library (used as a unique identifier for it)
        init_fn (function): init function for the class instance
    """
    global libraries_factory

    libraries_factory[name] = init_fn

def getLibFactory():
    """Return the library factory mapping.

    Return Value:
        library factory mapping: name => init_fn
    """
    return libraries_factory
