from lib_template import *

class TreckSeeker(Seeker):
    """Seeker (Identifier) for the Treck (Xilinx) closed source library."""

    # Library Name
    NAME = 'Treck'

    # Overridden base function
    def openSource(self):
        """Check if the library is an open source or closed source.

        Return Value:
            False (This is a closed source library)
        """
        return False

    # Overridden base function
    def searchLib(self, logger):
        """Check if the closed source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = 'tfRecvFromTo'

        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a key string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)

        # return the result
        return len(self._version_strings)

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
TreckSeeker.register(TreckSeeker.NAME, TreckSeeker)
