from lib_template import *

class mDNSSeeker(Seeker):
    """Seeker (Identifier) for the mDNSResponder open source library."""

    # Library Name
    NAME = 'mDNSResponder'
    VERSION_STRING = NAME

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)

        # return the result (artificial, as we don't yet support exact identification for this library)
        return 1 if len(self._version_strings) > 0 else 0

    # Overridden base function
    def identifyVersions(self, logger):
        """Identify the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        return [self.VERSION_UNKNOWN]


# Register our class
mDNSSeeker.register(mDNSSeeker.NAME, mDNSSeeker)
