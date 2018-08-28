from lib_template import *
import string

class LibpngSeeker(Seeker):
    # Library Name
    NAME = 'libpng'
    # version string marker
    VERSION_STRING = " libpng version "

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
                logger.debug("Located the copyright string of in address 0x%x", bin_str.ea)
                match_counter += 1
                # save the string for later
                self._copyright_string = copyright_string

        # return the result
        return match_counter

    def identifyVersion(self, logger):
        # extract the version from the copyright string
        start_index = self._copyright_string.find(self.VERSION_STRING) + len(self.VERSION_STRING)
        legal_chars = string.digits + '.'
        end_index = start_index
        # scan until we stop
        while self._copyright_string[end_index] in legal_chars:
            end_index += 1
        if self._copyright_string[end_index] == '.':
            end_index -= 1
        # return the result
        return self._copyright_string[start_index : end_index]

# Register our class
LibpngSeeker.register(LibpngSeeker.NAME, LibpngSeeker)