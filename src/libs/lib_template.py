from lib_factory import registerLibrary
import string

class Seeker(object):
    """Abstract class that represents a basic library seeker.

    Attributes
    ----------
        _all_strings (list): list of all of the string in the *.idb (to avoid re-generating this list)

    Static Attributes
    -----------------
        VERSION_UNKNOWN (str): the default value when we failed to fingerprint the version of a library
        NAME (str): name of the open source library (without versioning info)
    """

    VERSION_UNKNOWN = 'unknown'

    def __init__(self, all_strings):
        """Init the base seeker with useful data.

        Args:
            all_string (list): list of all of the strings in the *.idb (to avoid re-generating this list)
        """
        self._all_strings = all_strings

    def name(self):
        """Return the name of the library.

        Return Value:
            The textual name of the open source library
        """
        return self.NAME

    def openSource(self):
        """Check if the library is an open source or closed source.

        Return Value:
            True iff the library is an open source (True by default)
        """
        return True

    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        raise NotImplementedError("Subclasses should implement this!")

    def identifyVersions(self, logger):
        """Identifiy the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        raise NotImplementedError("Subclasses should implement this!")

    def extractVersion(self, raw_version_string, start_index=0, legal_chars=string.digits + '.'):
        """Extract the version of the library from the raw version string.

        Args:
            raw_version_string (str): raw version string
            start_index (int): start index for the version parsing (0 by default)
            legal_chars (string): set of legal chars for the version string (string.digits + '.' by default)

        Return Value:
            Textual ID of the library's version
        """
        end_index = start_index
        # scan until we stop
        while end_index < len(raw_version_string) and raw_version_string[end_index] in legal_chars:
            end_index += 1
        if end_index < len(raw_version_string) and raw_version_string[end_index] == '.':
            end_index -= 1
        # return the result
        return raw_version_string[start_index:end_index]

    @staticmethod
    def register(name, init_fn):
        """Register the library in the overall factory.

        Args:
            name (str): name of the open source library (used as a unique identifier for it)
            init_fn (function): init function for the class instance
        """
        registerLibrary(name, init_fn)
