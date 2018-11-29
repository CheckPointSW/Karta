from lib_template import *
import string

class LibpngSeeker(Seeker):
    # Library Name
    NAME = 'libpng'
    # version string marker
    VERSION_STRING = "libpng version "

    # Overriden base function
    def searchLib(self, logger):
        key_string = "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc."

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

        # return the result
        return len(self._version_strings)

    # Overriden base function
    def identifyVersions(self, logger):
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index = work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return results

# Register our class
LibpngSeeker.register(LibpngSeeker.NAME, LibpngSeeker)