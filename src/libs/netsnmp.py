from lib_template import *
import string

class NetSNMPSeeker(Seeker):
    # Library Name
    NAME = 'net-snmp'

    # Overriden base function
    def searchLib(self, logger):
        key_string = "NET-SNMP version: %s"

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
                if cur_str.startswith("5."):
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
NetSNMPSeeker.register(NetSNMPSeeker.NAME, NetSNMPSeeker)
