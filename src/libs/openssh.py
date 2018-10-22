from lib_template import *
import string

class OpensshSeeker(Seeker):
    # Library Name
    NAME = 'OpenSSH'
    # version string marker
    VERSION_STRING = "OpenSSH_"

    # Overriden base function
    def searchLib(self, logger):
        self._version_string = None
        # Now search
        match_counter = 0
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
                logger.debug("Located the version string of in address 0x%x", bin_str.ea)
                match_counter += 1
                # save the string for later
                self._version_string = version_string

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        # extract the version from the saved string
        work_str = self._version_string
        start_index = work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)
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
OpensshSeeker.register(OpensshSeeker.NAME, OpensshSeeker)
