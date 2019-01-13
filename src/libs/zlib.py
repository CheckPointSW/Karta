from lib_template import *
from collections  import defaultdict

class ZlibSeeker(Seeker):
    """Seeker (Identifier) for the zlib open source library."""

    # Library Name
    NAME = 'zlib'
    # version string marker
    VERSION_STRING = " deflate "

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = " Jean-loup Gailly "
        error_strings = ["need dictionary", "stream end", "file error", "stream error", "data error", "buffer error", "incompatible version"]
        key_error_strings = [error_strings[0], error_strings[-1]]
        matched_error_strings = defaultdict(list)

        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for the inner version string
                if self.VERSION_STRING not in copyright_string:
                    # false match
                    continue
                # valid match
                logger.debug("Located a copyright string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(copyright_string)
            # use the error strings as backups
            elif str(bin_str) in key_error_strings and len(self._version_strings) == 0:
                logger.debug("Located a key error string of %s in address 0x%x", self.NAME, bin_str.ea)
                matched_error_strings[str(bin_str)].append(bin_str)

        # check if we need the backup
        if len(self._version_strings) == 0 and len(matched_error_strings.keys()) == len(key_error_strings):
            logger.debug("We found the library, however we can't resolve its version :(")
            self._version_strings = [self.VERSION_UNKNOWN]

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
        # check for the error string backup case
        if len(self._version_strings) == 1 and self.VERSION_UNKNOWN in self._version_strings:
            return self._version_strings
        # continue as before
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return results


# Register our class
ZlibSeeker.register(ZlibSeeker.NAME, ZlibSeeker)
