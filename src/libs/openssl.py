from lib_template import *
import string

class OpenSSLSeeker(Seeker):
    # Library Name
    NAME = 'OpenSSL'
    # version string marker
    VERSION_STRING = " part of OpenSSL "

    # Overriden base function
    def searchLib(self, logger):
        key_string = self.VERSION_STRING
        ids = ['SHA1', 'SHA-256', 'SHA-512', 'SSLv3', 'TLSv1', 'ASN.1', 'EVP', 'RAND', 'RSA', 'Big Number']

        # Now search
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for a supporting key word id
                if len(filter(lambda id : id in copyright_string, ids)) == 0:
                    # false match
                    continue
                # check for a duplicate inside the same library
                if match_counter >= 1 and self._copyright_string in copyright_string :
                    continue
                # valid match
                logger.debug("Located the copyright string of in address 0x%x", bin_str.ea)
                match_counter += 1
                # save the string for later
                self._copyright_string = copyright_string[copyright_string.find(key_string) : ]

        # return the result
        return match_counter

    # Overriden base function
    def identifyVersion(self, logger):
        # extract the version from the copyright string
        start_index = self._copyright_string.find(self.NAME) + len(self.NAME) + 1 # skip the space
        legal_chars = string.digits + string.ascii_lowercase + '.'
        end_index = start_index
        # scan until we stop
        while self._copyright_string[end_index] in legal_chars:
            end_index += 1
        if self._copyright_string[end_index] == '.':
            end_index -= 1
        # return the result
        return self._copyright_string[start_index : end_index]

# Register our class
OpenSSLSeeker.register(OpenSSLSeeker.NAME, OpenSSLSeeker)
