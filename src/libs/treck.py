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
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                # valid match
                logger.debug("Located the key string of in address 0x%x", bin_str.ea)
                match_counter += 1

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        return self.VERSION_UNKNOWN

# Register our class
TreckSeeker.register(TreckSeeker.NAME, TreckSeeker)
