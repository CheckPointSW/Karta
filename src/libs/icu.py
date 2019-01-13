from lib_template import *
import string

class icuSeeker(Seeker):
    """Seeker (Identifier) for the icu (unicode) open source library."""

    # Library Name
    NAME = 'icu'

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = "ICU_TIMEZONE_FILES_DIR"

        # Now search
        key_indices = []
        for idx, bin_str in enumerate(self._all_strings):
            # we have a match
            if key_string in str(bin_str):
                logger.debug("Located a key string of %s in address 0x%x", self.NAME, bin_str.ea)
                key_indices.append(idx)
                break

        # Now check for the version string
        self._version_strings = []
        for key_index in key_indices:
            for bin_str in self._all_strings[max(key_index - 10000, 0):min(key_index + 10000, len(self._all_strings))]:
                cur_str = str(bin_str)
                if cur_str.find('.') == 2 and len(cur_str) == 4 and cur_str[0] in string.digits and cur_str[1] in string.digits and cur_str[3] in string.digits:
                    logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                    self._version_strings.append(cur_str)
                    break
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
        # return the result
        return self._version_strings


# Register our class
icuSeeker.register(icuSeeker.NAME, icuSeeker)
