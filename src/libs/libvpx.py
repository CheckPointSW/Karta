from lib_template import *
import string

class libvpxSeeker(Seeker):
    # Library Name
    NAME = 'libvpx'
    # version string marker
    VERSION_STRING_VP8 = "WebM Project VP8 Decoder v"
    VERSION_STRING_VP9 = "WebM Project VP9 Decoder v"

    # Overriden base function
    def searchLib(self, logger):
        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if str(bin_str).startswith(self.VERSION_STRING_VP8) or str(bin_str).startswith(self.VERSION_STRING_VP9):
                version_string = str(bin_str)
                # valid match
                logger.debug("Located a version string of %s in address 0x%x", self.NAME, bin_str.ea)
                # save the string for later (only if not a duplicate)
                present_string = self.VERSION_STRING_VP8 if self.VERSION_STRING_VP8 in version_string else self.VERSION_STRING_VP9
                other_string   = self.VERSION_STRING_VP9 if self.VERSION_STRING_VP8 in version_string else self.VERSION_STRING_VP9
                if version_string.replace(present_string, other_string) not in self._version_strings:
                    self._version_strings.append(version_string)

        # return the result
        return len(self._version_strings)

    # Overriden base function
    def identifyVersions(self, logger):
        results = set()
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.add(self.extractVersion(work_str, start_index = len(self.VERSION_STRING_VP8)))
        # return the result
        return list(results)

# Register our class
libvpxSeeker.register(libvpxSeeker.NAME, libvpxSeeker)
