from lib_template import *
import string

class LibTIFFSeeker(Seeker):
    # Library Name
    NAME = 'libtiff'
    # version string marker
    VERSION_STRING = "LIBTIFF, Version "
    SANITY_STRING = "TIFFRasterScanlineSize64"

    # Overriden base function
    def searchLib(self, logger):
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

    # Overriden base function
    def identifyVersions(self, logger):
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index = work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        if len(results) == 0 and self._sanity_exists:
            return [self.VERSION_UNKNOWN]
        # return the result
        return results

# Register our class
LibTIFFSeeker.register(LibTIFFSeeker.NAME, LibTIFFSeeker)
