from lib_template import *
import string

class LibJPEGSeeker(Seeker):
    """Seeker (Identifier) for the libjpeg (ITU) open source library."""

    # Library Name
    NAME = 'libjpeg'
    # version string marker
    VERSION_STRING = ", Thomas G. Lane, Guido Vollbeding"

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
        for bin_idx, bin_str in enumerate(self._all_strings):
            # we have a match
            if self.VERSION_STRING in str(bin_str) and bin_idx + 1 < len(self._all_strings):
                # double check it
                wanted_string_raw = self._all_strings[bin_idx + 1]
                wanted_string = str(wanted_string_raw)
                try:
                    if wanted_string.count("-") == 2 and len(wanted_string.split("-")[-1]) == 4:
                        year = int(wanted_string.split("-")[-1])
                    # if both libraries (Karta and libjpeg) will be used in 2100, we will other things to worry about
                    if year < 1900 or 2100 < year:
                        continue
                except ValueError:
                    continue
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, wanted_string_raw.ea)
                # save the string for later
                self._version_strings.append(wanted_string)

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
            results.append(self.extractVersion(work_str, legal_chars=string.digits + string.ascii_lowercase + '.'))
        # return the result
        return results


# Register our class
LibJPEGSeeker.register(LibJPEGSeeker.NAME, LibJPEGSeeker)
