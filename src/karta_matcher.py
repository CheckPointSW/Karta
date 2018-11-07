from config.utils           import *
from disassembler.factory   import createDisassemblerHandler
from match_library          import startMatch
from libs                   import lib_factory

######################
## Global Variables ##
######################

config_path         = None      # path to the configuration directory (including the *.json files with the pre-compiled libraries)
logger              = None      # elementals logger instance

def matchLibrary(lib_name, lib_version):
    """Checks if the library was already compiled, and matches it

    Args:
        lib_name (str): name of the open source library
        lib_version (str): version string for the open source library that was found
    """

    # Check for existence
    config_name = constructConfigPath(lib_name, lib_version)
    cur_config_path = os.path.join(config_path, config_name)
    if not os.path.exists(cur_config_path) :
        logger.error("Missing configuration file (%s) for \"%s\" Version: \"%s\"", config_name, lib_name, lib_version)
        return

    # Start the actual matching
    logger.addIndent()
    logger.info("Starting to match \"%s\" Version: \"%s\"", lib_name, lib_version)
    startMatch(cur_config_path, logger)
    logger.info("Finished the matching")
    logger.removeIndent()

def matchLibraries():
    """Iterates over the supported libraries, and activates each of them"""
    libraries_factory = lib_factory.getLibFactory()
    for lib_name in libraries_factory :
        # create the instance
        lib_instance = libraries_factory[lib_name](disas.strings())
        # stopped when the first closed source shows up
        if not lib_instance.openSource() :
            break
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

def pluginMain():
    """Main function for the Karta (matcher) plugin"""
    global disas, logger, config_path

    # init our disassembler handler
    disas = createDisassemblerHandler(None)

    # Get the configuration values from the user
    config_values = disas.configForm()
    if config_values is None:
        return

    # store them / use them now for initialization
    config_path = config_values["config_path"]
    if config_values["is_windows"] :
        setWindowsMode()

    working_path = os.path.split(disas.databaseFile())[0]

    log_files  = []
    #log_files += [(os.path.join(working_path, "%s_debug.log"   % (LIBRARY_NAME)), "w", logging.DEBUG)]
    log_files += [(os.path.join(working_path, "%s_info.log"    % (LIBRARY_NAME)), "w", logging.INFO)]
    log_files += [(os.path.join(working_path, "%s_warning.log" % (LIBRARY_NAME)), "w", logging.WARNING)]
    logger = Logger(LIBRARY_NAME, log_files, use_stdout = False, min_log_level = logging.INFO)
    initUtils(logger, disas)
    logger.info("Started the Script")

    # Active the matching mode
    setMatchingMode()

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")
    all_bin_strings = disas.strings()

    # Start matching the libraries
    logger.info("Going to locate and match the open source libraries")
    matchLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

    # Notify the user about the logs
    disas.messageBox("Saved the logs to directory: %s" % (working_path))

# Start to analyze the file
pluginMain()
