import ida_api as ida
from lib_factory import registerLibrary

class Seeker(object):
    """Abstract class that represents a basic library seeker

    Attributes:
        _all_strings (list): list of all of the string in the *.idb (to avoid re-generating this list)

    Static Attributes:
        VERSION_UNKNOWN (str): the default value when we failed to fingerprint the version of a library
        NAME (str): name of the open source library (without versioning info)
    """

    VERSION_UNKNOWN = 'unknown'

    def __init__(self, all_strings):
        """Inits the base seeker with useful data.

        Args:
            all_string (list): list of all of the strings in the *.idb (to avoid re-generating this list)
        """
        self._all_strings = all_strings

    def name(self):
        """Returns the name of the library

        Return Value:
            The textual name of the open source library
        """
        return self.NAME

    def openSource(self):
        """Checks if the library is an open source or closed source

        Return Value:
            True iff the library is an open source (True by default)
        """
        return True
        
    def searchLib(self, logger):
        """Checks if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        raise NotImplementedError("Subclasses should implement this!")

    def identifyVersion(self, logger):
        """Identifies the version of the library (assuming it was already found)

        Assumptions:
            1. searchLib() was called before calling identifyVersion()
            2. The call to searchLib() returned True

        Args:
            logger (logger): elementals logger instance

        Return Value:
            Textual ID of the library's version
        """
        raise NotImplementedError("Subclasses should implement this!")

    @staticmethod
    def register(name, init_fn):
        """Registers the library in the overall factory

        Args:
            name (str): name of the open source library (used as a unique identifier for it)
            init_fn (function): init function for the class instance
        """
        registerLibrary(name, init_fn)
