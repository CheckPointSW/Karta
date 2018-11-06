from lib_template import *
import string

class LibpngSeeker(Seeker):
    # Library Name
    NAME = 'libpng'
    # version string marker
    VERSION_STRING = "libpng version "

    # Overriden base function
    def searchLib(self, logger):
        key_string = "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc."

        # Now search
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for the inner version string
                if self.VERSION_STRING not in copyright_string:
                    # false match
                    continue
                # valid match
                logger.debug("Located the copyright string in address 0x%x", bin_str.ea)
                match_counter += 1
                # save the string for later
                self._copyright_string = copyright_string

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        # extract the version from the saved string
        work_str = self._copyright_string
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
LibpngSeeker.register(LibpngSeeker.NAME, LibpngSeeker)