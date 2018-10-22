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
        match_counter = 0
        key_index = None
        for idx, bin_str in enumerate(self._all_strings):
            # we have a match
            if key_string in str(bin_str):
                logger.debug("Located the key string in address 0x%x", bin_str.ea)
                match_counter += 1
                if match_counter == 1:
                    key_index = idx
                break

        # Now check for the version string
        self._version_string = None
        if key_index is not None and match_counter == 1:
            for bin_str in self._all_strings[max(key_index - 10000, 0) : min(key_index + 10000, len(self._all_strings))] :
                cur_str = str(bin_str)
                if cur_str.index('-') != -1 and cur_str.split('-')[1][:3] in extra_parts:
                    logger.debug("Located the version string in address 0x%x", bin_str.ea)
                    self._version_string = cur_str
                    break
        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        # sanity check
        if self._version_string is None:
            logger.warning("Failed to find the version string of %s", self.NAME)
            return self.VERSION_UNKNOWN
        work_str = self._version_string
        # extract the version from the saved string
        start_index = 0
        legal_chars = string.digits + '.'
        end_index = start_index
        # scan until we stop
        while end_index < len(work_str) and work_str[end_index] in legal_chars:
            end_index += 1
        if end_index < len(work_str) and work_str[end_index] == '.':
            end_index -= 1
        # return the result
        return work_str[start_index : end_index]

# Register our class
Libxml2Seeker.register(Libxml2Seeker.NAME, Libxml2Seeker)
