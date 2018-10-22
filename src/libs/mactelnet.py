from lib_template import *
import string

class MACTelnetSeeker(Seeker):
    # Library Name
    NAME = 'MAC-Telnet'
    # version string marker
    VERSION_STRING = "MAC-Telnet "
    DEAMON_STRING  = "MAC-Telnet Daemon "

    # Overriden base function
    def searchLib(self, logger):
        # Now search
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            if self.VERSION_STRING in str(bin_str):
                version_string = str(bin_str)
                # check for the inner version string
                if self.DEAMON_STRING not in version_string:
                    # false match
                    continue
                # valid match
                logger.debug("Located the version string in address 0x%x", bin_str.ea)
                match_counter += 1
                # save the string for later
                self._version_string = version_string

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        # extract the version from the saved string
        work_str = self._version_string
        start_index = work_str.find(self.DEAMON_STRING) + len(self.DEAMON_STRING)
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
MACTelnetSeeker.register(MACTelnetSeeker.NAME, MACTelnetSeeker)
