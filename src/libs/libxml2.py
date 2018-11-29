from lib_template import *
import string

class Libxml2Seeker(Seeker):
    # Library Name
    NAME = 'libxml2'

    # Overriden base function
    def searchLib(self, logger):
        extra_parts = ['CVS', 'SVN', 'GIT']
        key_string = ": program compiled against libxml %d using older %d\n"

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
            for bin_str in self._all_strings[max(key_index - 10000, 0) : min(key_index + 10000, len(self._all_strings))] :
                cur_str = str(bin_str)
                if cur_str.find('-') != -1 and cur_str.split('-')[1][:3] in extra_parts:
                    logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                    self._version_strings.append(cur_str)
                    break
        # return the result
        return len(self._version_strings)

    # Overriden base function
    def identifyVersions(self, logger):
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str))
        # return the result
        return results

# Register our class
Libxml2Seeker.register(Libxml2Seeker.NAME, Libxml2Seeker)
