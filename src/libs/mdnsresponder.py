from lib_template import *
import string

class mDNSSeeker(Seeker):
    # Library Name
    NAME = 'mDNSResponder'

    # Overriden base function
    def searchLib(self, logger):
        key_string = 'mDNSResponder'

        # Now search
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                # valid match
                logger.debug("Located the key string in address 0x%x", bin_str.ea)
                match_counter += 1

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        return self.VERSION_UNKNOWN

# Register our class
mDNSSeeker.register(mDNSSeeker.NAME, mDNSSeeker)
