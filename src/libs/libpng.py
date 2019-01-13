from lib_template import *
from config.utils import getDisas

class LibpngSeeker(Seeker):
    """Seeker (Identifier) for the libpng open source library."""

    # Library Name
    NAME = 'libpng'
    # version string marker
    VERSION_STRING = "libpng version "

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc."
        backup_string = "Incompatible libpng version in application and library"
        # Now search
        backup_strings = []
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for the inner version string
                if self.VERSION_STRING not in copyright_string:
                    # false match
                    continue
                # valid match
                logger.debug("Located a copyright string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                self._version_strings.append(copyright_string)
            # partial match, only the backup
            if backup_string in str(bin_str) and len(self._version_strings) == 0:
                # valid placeholder
                logger.debug("Located a place holder string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later
                backup_strings.append(bin_str)

        # check if we need the backups
        if len(self._version_strings) == 0 and len(backup_strings) > 0:
            clue_strings = []
            seen_funcs   = []
            disas = getDisas()
            # collect all of the strings that are referenced by the caller function
            for backup_string in backup_strings:
                for dref in disas.drefsTo(backup_string.ea):
                    caller_func = disas.funcAt(dref)
                    if caller_func is not None and caller_func not in seen_funcs:
                        # collect the strings
                        clue_strings += disas.stringsInFunc(disas.funcStart(caller_func))
                        # mark that we saw this function
                        seen_funcs.append(caller_func)
            # drop all illegal options
            clue_strings = filter(lambda x: self.extractVersion(x) == x, clue_strings)
            # the version will be the most popular string
            chosen_string = max(set(clue_strings), key=clue_strings.count)
            logger.debug("The chosen version string is: %s", chosen_string)
            self._version_strings.append(self.VERSION_STRING + chosen_string)

        # return the result
        return len(self._version_strings)

    # Overridden base function
    def identifyVersions(self, logger):
        """Identify the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.append(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return results


# Register our class
LibpngSeeker.register(LibpngSeeker.NAME, LibpngSeeker)
