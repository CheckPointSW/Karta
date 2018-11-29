from lib_template import *
import string

class OpensshSeeker(Seeker):
    # Library Name
    NAME = 'OpenSSH'
    # version string marker
    VERSION_STRING = "OpenSSH_"

    # Overriden base function
    def searchLib(self, logger):
        self._version_strings = []
        # Now search
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # catch false / duplicates
                if '*' in version_string or \
                    (self._version_string is not None and version_string in self._version_string) or \
                    (self._version_string is not None and self._version_string in version_string) :
                    continue
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)

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
OpensshSeeker.register(OpensshSeeker.NAME, OpensshSeeker)
