from lib_template import *

class MACTelnetSeeker(Seeker):
    """Seeker (Identifier) for the MAC-Telnet open source library."""

    # Library Name
    NAME = 'MAC-Telnet'
    # version string marker
    VERSION_STRING = "MAC-Telnet "
    DEAMON_STRING  = "MAC-Telnet Daemon "

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
                # check for the inner version string
                if self.DEAMON_STRING not in version_string:
                    # false match
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
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.DEAMON_STRING) + len(self.DEAMON_STRING)))
        # return the result
        return results


# Register our class
MACTelnetSeeker.register(MACTelnetSeeker.NAME, MACTelnetSeeker)
