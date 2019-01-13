from lib_template import *

class LibTIFFSeeker(Seeker):
    """Seeker (Identifier) for the libtiff open source library."""

    # Library Name
    NAME = 'libtiff'
    # version string marker
    VERSION_STRING = "LIBTIFF, Version "
    SANITY_STRING = "TIFFRasterScanlineSize64"

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
        self._sanity_exists = False
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)
            # check the sanity string
            if self.SANITY_STRING in str(bin_str):
                self._sanity_exists = True

        # return the result
        if self._sanity_exists and len(self._version_strings) == 0:
            return 1
        else:
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
        if len(results) == 0 and self._sanity_exists:
            return [self.VERSION_UNKNOWN]
        # return the result
        return results


# Register our class
LibTIFFSeeker.register(LibTIFFSeeker.NAME, LibTIFFSeeker)
