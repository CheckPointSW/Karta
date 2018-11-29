from lib_template import *
import string

class mDNSSeeker(Seeker):
    # Library Name
    NAME = 'mDNSResponder'
    VERSION_STRING = NAME

    # Overriden base function
    def searchLib(self, logger):
        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)

        # return the result
        return len(self._version_strings)

    # Overriden base function
    def identifyVersions(self, logger):
        return self.VERSION_UNKNOWN

# Register our class
mDNSSeeker.register(mDNSSeeker.NAME, mDNSSeeker)
