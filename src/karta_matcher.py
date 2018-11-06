from utils          import *
from match_library  import startMatch
from libs           import lib_factory
from ida_api        import *

######################
## Global Variables ##
######################

config_path         = None      # path to the configuration directory (including the *.json files with the pre-compiled libraries)
all_bin_strings     = None      # list of all of the binary strings in the *.idb
logger              = None      # elementals logger instance

class MessageBox(idaapi.Form):
    """Wrapper class that represents a GUI MessageBox"""
    def __init__(self, text):
        """Basic Ctor for the class

        Args:
            text (str): Text to be shown by the message box
        """
        # dialog content
        dialog_content = """%s
                            %s
                          """ % (LIBRARY_NAME, text)
        idaapi.Form.__init__(self, dialog_content, {})

class ConfigForm(idaapi.Form):
    """Wrapper class that represents the GUI configuration form for Karta's scripts

    Attributes:
        _config_path (str): path to the chosen configuration directory (that includes the *.json files)
        _is_windows (bool): True iff the user specified this as a windows binary (False by default)
    """
    def __init__(self):
        """Basic Ctor for the Form class"""
        # dialog content
        dialog_content = """%s
                            Please insert the path to configuration directory that holds the *.json files
                            to match against the current binary.

                            <#Select a *.json configs directory for %s exported libraries       #Configs Directory    :{_config_path}>
                            <#Enable this option for binaries compiled for Windows              #Is Windows binary    :{_is_windows}>{_check_group}>
                          """ % (LIBRARY_NAME, LIBRARY_NAME)
        # argument parsing
        args = {'_config_path'       : idaapi.Form.DirInput(swidth=65),
                '_check_group'       : idaapi.Form.ChkGroupControl(("_is_windows",)),
                }
        idaapi.Form.__init__(self, dialog_content, args)

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
    startMatch(cur_config_path, lib_name, logger)
    logger.info("Finished the matching")
    logger.removeIndent()

def matchLibraries():
    """Iterates over the supported libraries, and activates each of them"""
    libraries_factory = lib_factory.getLibFactory()
    for lib_name in libraries_factory :
        # create the instance
        lib_instance = libraries_factory[lib_name](all_bin_strings)
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
    global logger, all_bin_strings, config_path

    # Learn what is our directory
    c = ConfigForm()
    c.Compile()
    if not c.Execute():
        return

    # store it for future use
    config_path = c._config_path.value
    if c._is_windows.checked :
        setWindowsMode()

    working_path = os.path.split(idc.GetIdbPath())[0]

    log_files  = []
    #log_files += [(os.path.join(working_path, "%s_debug.log"   % (LIBRARY_NAME)), "w", logging.DEBUG)]
    log_files += [(os.path.join(working_path, "%s_info.log"    % (LIBRARY_NAME)), "w", logging.INFO)]
    log_files += [(os.path.join(working_path, "%s_warning.log" % (LIBRARY_NAME)), "w", logging.WARNING)]
    logger = Logger(LIBRARY_NAME, log_files, use_stdout = False, min_log_level = logging.INFO)
    logger.linkHandler(IdaLogHandler())
    logger.info("Started the Script")

    # Active the matching mode
    setMatchingMode()

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")
    all_bin_strings = idaStringList()

    # Start matching the libraries
    logger.info("Going to locate and match the open source libraries")
    matchLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

    m = MessageBox("Saved the logs to directory: %s" % (working_path))
    m.Compile()
    m.Execute()

# Start to analyze the file
pluginMain()
