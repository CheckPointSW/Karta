import logging
from elementals import Logger

from karta.config.utils           import *
from karta.disassembler.factory   import createDisassemblerHandler
from karta.matching_engine        import KartaMatcher
from karta.libs                   import lib_factory

######################
## Global Variables ##
######################

config_path         = None      # path to the configuration directory (including the *.json files with the pre-compiled libraries)
logger              = None      # elementals logger instance

def startMatch(config_file, lib_name):
    """Start matching the wanted source library to the loaded binary.

    Args:
        config_file (path): path to the library's configuration file
        lib_name (str): name of the open source library
    """
    disas = getDisas()

    # always init the utils before we start
    initUtils(logger, disas, invoked_before=True)

    # Load the configuration file
    fd = open(config_file, "r")
    config_dict = json.load(fd)
    fd.close()

    # Load the accumulated knowledge for this binary file
    knowledge_config = loadKnowledge()
    manual_anchors = []
    if knowledge_config is not None and JSON_TAG_MANUAL_ANCHORS in knowledge_config:
        all_manual_anchors = knowledge_config[JSON_TAG_MANUAL_ANCHORS]
        if lib_name in all_manual_anchors:
            logger.debug("Loading manual anchors")
            logger.addIndent()
            for src_index in all_manual_anchors[lib_name]:
                src_file, src_name, hex_ea, bin_ea = all_manual_anchors[lib_name][src_index]
                logger.debug(f"Manual anchor: {src_name} ({int(src_index)}), 0x{bin_ea:x}")
                manual_anchors.append((int(src_index), bin_ea))
            logger.removeIndent()
    else:
        logger.debug("Has no manual anchors")

    # Init out matching engine
    matching_engine = KartaMatcher(logger, disas)

    try:
        # Load the source functions, and prepare them for use
        matching_engine.loadAndPrepareSource(config_dict[JSON_TAG_FILES])

        # Load and match the anchor functions
        matching_engine.loadAndMatchAnchors(config_dict[JSON_TAG_ANCHORS], manual_anchors)

        # Locate the file boundaries in the binary functions list
        matching_engine.locateFileBoundaries()

        # Prepare the located binary functions for first use
        matching_engine.prepareBinFunctions()

        # Now try to match all of the files
        matching_engine.matchFiles()

        # Generate the suggested function names
        matching_engine.generateSuggestedNames()

        # Show the GUI window with the matches
        match_entries, external_match_entries = matching_engine.prepareGUIEntries()
        matching_engine.showResultsGUIWindow(match_entries, external_match_entries)
    except KartaException:
        logger.error("Critical error, matching was stopped")

def matchLibrary(lib_name, lib_version):
    """Check if the library was already compiled, and matches it.

    Args:
        lib_name (str): name of the open source library
        lib_version (str): version string for the open source library that was found
    """
    # Check for existence
    config_name = constructConfigPath(lib_name, lib_version)
    cur_config_path = os.path.join(config_path, config_name)
    if not os.path.exists(cur_config_path):
        logger.error(f"Missing configuration file ({config_name}) for \"{lib_name}\" Version: \"{lib_version}\"")
        return

    # Start the actual matching
    logger.addIndent()
    logger.info(f"Starting to match \"{lib_name}\" Version: \"{lib_version}\"")
    startMatch(cur_config_path, lib_name)
    logger.info("Finished the matching")
    logger.removeIndent()

def matchLibraries():
    """Iterate over the supported libraries, and activates each of them."""
    # Load the accumulated knowledge for this binary file
    knowledge_config = loadKnowledge()
    if knowledge_config is not None and JSON_TAG_MANUAL_VERSIONS in knowledge_config:
        all_manual_versions = knowledge_config[JSON_TAG_MANUAL_VERSIONS]
    else:
        all_manual_versions = []
        logger.debug("Has no manual versions")
    libraries_factory = lib_factory.getLibFactory()
    for lib_name in libraries_factory:
        # create the instance
        lib_instance = libraries_factory[lib_name](disas.strings())
        # stopped when the first closed source shows up
        if not lib_instance.openSource():
            break
        # check for a pre-supplied manual version
        if lib_name in all_manual_versions:
            manual_versions = all_manual_versions[lib_name]
            logger.debug(f"Manual versions: {', '.join(manual_versions)}")
        else:
            manual_versions = []
        logger.debug(f"Searching for library \"{lib_name}\" in the binary")
        logger.addIndent()
        # search for it
        match_counter = lib_instance.searchLib(logger)
        # make sure we have a single match
        if match_counter > 1:
            logger.warning(f"Found multiple instances of \"{lib_name}\" - multiple instances are not supported right now")
        elif match_counter == 0:
            logger.info(f"Did not find \"{lib_name}\" in the binary")
        # exact, single match
        else:
            logger.info(f"Successfully found \"{lib_name}\" in the binary")
            # identify it's version
            lib_versions = lib_instance.identifyVersions(logger)
            # check if we need to identify this one
            if lib_versions[0] == lib_instance.VERSION_UNKNOWN:
                if len(manual_versions) != 1:
                    logger.warning(f"Can't match an unknown version of library \"{lib_name}\"")
                    continue
                actual_version = manual_versions[0]
            else:
                actual_version = lib_versions[0]
            # now try to match the library
            matchLibrary(lib_name, actual_version)
        # continue to the next library
        logger.removeIndent()

def pluginMain():
    """Run the Karta (matcher) plugin."""
    global disas, logger, config_path

    # Use the basic logger on the init phase
    init_logger = Logger(LIBRARY_NAME)
    init_logger.linkHandler(logging.FileHandler(constructInitLogPath(), "w"))
    disas = createDisassemblerHandler(init_logger)
    # In case of a dependency issue, disas will be None
    if disas is None:
        return

    # Get the configuration values from the user
    config_values = disas.configForm()
    if config_values is None:
        return

    # store them / use them now for initialization
    config_path = config_values["config_path"]
    if config_values["is_windows"]:
        setWindowsMode()

    working_path = os.path.split(disas.databaseFile())[0]

    log_files  = []
#    log_files += [(os.path.join(working_path, LIBRARY_NAME + "_debug.log"),   "w", logging.DEBUG)]
    log_files += [(os.path.join(working_path, LIBRARY_NAME + "_info.log"),    "w", logging.INFO)]
    log_files += [(os.path.join(working_path, LIBRARY_NAME + "_warning.log"), "w", logging.WARNING)]
    logger = Logger(LIBRARY_NAME, log_files, use_stdout=False, min_log_level=logging.INFO)
    initUtils(logger, disas)
    logger.info("Started the Script")

    # Active the matching mode
    setMatchingMode()

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")

    # Start matching the libraries
    logger.info("Going to locate and match the open source libraries")
    matchLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

    # Notify the user about the logs
    disas.messageBox(f"Saved the logs to directory: {working_path}")


# Start to analyze the file
pluginMain()
