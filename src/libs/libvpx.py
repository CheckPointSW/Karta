from lib_template import *

class libvpxSeeker(Seeker):
    """Seeker (Identifier) for the libvpx (codec) open source library."""

    # Library Name
    NAME = 'libvpx'
    # version string marker
    VERSION_STRING_VP8 = "WebM Project VP8 Decoder v"
    VERSION_STRING_VP9 = "WebM Project VP9 Decoder v"

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
            if str(bin_str).startswith(self.VERSION_STRING_VP8) or str(bin_str).startswith(self.VERSION_STRING_VP9):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later (only if not a duplicate)
                present_string = self.VERSION_STRING_VP8 if self.VERSION_STRING_VP8 in version_string else self.VERSION_STRING_VP9
                other_string   = self.VERSION_STRING_VP9 if self.VERSION_STRING_VP8 in version_string else self.VERSION_STRING_VP9
                if version_string.replace(present_string, other_string) not in self._version_strings:
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
        results = set()
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.add(self.extractVersion(work_str, start_index=len(self.VERSION_STRING_VP8)))
        # return the result
        return list(results)


# Register our class
libvpxSeeker.register(libvpxSeeker.NAME, libvpxSeeker)
