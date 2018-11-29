from lib_template import *
import string

class TreckSeeker(Seeker):
    # Library Name
    NAME = 'Treck'

    # Overriden base function
    def openSource(self):
        return False

    # Overriden base function
    def searchLib(self, logger):
        key_string = 'tfRecvFromTo'

        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a key string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(version_string)

        # return the result
        return len(self._version_strings)

    # Overriden base function
    def identifyVersions(self, logger):
        return self.VERSION_UNKNOWN

# Register our class
TreckSeeker.register(TreckSeeker.NAME, TreckSeeker)
