from lib_template import *

class gSOAPSeeker(Seeker):
    """Seeker (Identifier) for the gSOAP open source library."""

    # Library Name
    NAME = 'gSOAP'
    # version string marker
    VERSION_STRING = "gSOAP/2."

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        # Now search
        self._version_strings = set()
        for bin_str in self._all_strings:
            # we have a match
            if str(bin_str).startswith(self.VERSION_STRING):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.add(version_string)

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
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING.split('/')[0]) + 1))
        # return the result
        return results


# Register our class
gSOAPSeeker.register(gSOAPSeeker.NAME, gSOAPSeeker)
