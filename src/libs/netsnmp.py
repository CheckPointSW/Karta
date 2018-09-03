from lib_template import *
import string

class NetSNMPSeeker(Seeker):
    # Library Name
    NAME = 'net-snmp'

    # Overriden base function
    def searchLib(self, logger):
        key_string = "snmp_parse_var_op"

        # Now search
        match_counter = 0
        key_index = None
        for idx, bin_str in enumerate(self._all_strings):
            # we have a match
            if key_string in str(bin_str):
                logger.debug("Located the key string in address 0x%x", bin_str.ea)
                match_counter += 1
                if match_counter == 0:
                    key_index = idx
                break

        # Now check for the version string
        self._version_string = None
        if key_index is not None and match_counter == 1:
            for bin_str in self._all_strings[max(key_index - 10000, 0) : min(key_index + 10000, len(self._all_strings))] :
                cur_str = str(bin_str)
                if cur_str.startswith("5."):
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
        # extract the version from the saved string
        work_str = self._version_string
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
NetSNMPSeeker.register(NetSNMPSeeker.NAME, NetSNMPSeeker)
