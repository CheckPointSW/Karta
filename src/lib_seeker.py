from utils          import *
from seek_binary    import startMatch
from libs           import lib_factory

import ida_api as ida

######################
## Global Variables ##
######################

workdir_path        = None      # path to the working directory (including the databases with the pre-compiled libraries)

all_bin_strings     = None      # list of all of the binary strings in the *.idb

logger              = None      # elementals logger instance

def matchLibrary(lib_name, lib_version):
    """Checks if the library was already compiled, and matches it"""

    # TODO: no check right now

    # Start the actual matching
    logger.addIndent()
    logger.info("Starting to match \"%s\" Version: \"%s\"", lib_name, lib_version)
    # startMatch(workdir_path, logger)
    logger.info("Finished the matching")
    logger.removeIndent()

def seekLibraries():
    """Iterates over the supported libraries, and activates each of them"""
    libraries_factory = lib_factory.getLibFactory()
    for lib_name in libraries_factory:
        # create the instance
        lib_instance = libraries_factory[lib_name](all_bin_strings)
        logger.debug("Searching for library \"%s\" in the binary", lib_name)
        logger.addIndent()
        # search for it
        match_counter = lib_instance.searchLib(logger)
        # make sure we have a single match
        if match_counter > 1:
            logger.warning("Found multiple instance of \"%s\" - multiple instances are not supported right now", lib_name)
        elif match_counter == 0:
            logger.info("Did not find \"%s\" in the binary", lib_name)
        # exact, single match
        else:
            logger.info("Successfully found \"%s\" in the binary", lib_name)
            # identify it's version
            lib_version = lib_instance.identifyVersion(logger)
            # now try to match the library
            matchLibrary(lib_name, lib_version)
        # continue to the next library
        logger.removeIndent()

def pluginMain(state_path):
    """Main function for the LibSeeker plugin

    Args:
        state_path (str): path to the stored state files
    """
    global logger, all_bin_strings, workdir_path

    # store it for future use
    workdir_path = state_path

    log_files  = []
#    log_files += [(os.path.join(workdir_path, "debug.log"), "w", logging.DEBUG)]
    log_files += [(os.path.join(workdir_path, "info.log"), "w", logging.INFO)]
    log_files += [(os.path.join(workdir_path, "warning.log"), "w", logging.WARNING)]
    logger = Logger(LIBRARY_NAME, log_files, use_stdout = False, min_log_level = logging.INFO)
    logger.linkHandler(ida.IdaLogHandler())
    logger.info("Started the Script")

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")
    all_bin_strings = ida.stringList()

    # Start seeking the libraries
    logger.info("Going to seek the open source libraries")
    seekLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

# Start to analyze the file
#pluginMain('/home/eyalitki/Documents/Tools/SrcToBin/tests/libpng-1.2.29')
#pluginMain('/home/eyalitki/Documents/Tools/SrcToBin/tests/zlib-1.2.3')
pluginMain('/home/eyalitki/Documents/Tools/SrcToBin/tests/openssl-1.0.1j')
