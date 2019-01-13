from lib_template import *

class OpensshSeeker(Seeker):
    """Seeker (Identifier) for the OpenSSH open source library."""

    # Library Name
    NAME = 'OpenSSH'
    # version string marker
    VERSION_STRING = "OpenSSH_"

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        self._version_strings = []
        # Now search
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # catch false / duplicates
                if '*' in version_string or \
                        (self._version_string is not None and version_string in self._version_string) or \
                        (self._version_string is not None and self._version_string in version_string):
                    continue
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
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
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return results


# Register our class
OpensshSeeker.register(OpensshSeeker.NAME, OpensshSeeker)
