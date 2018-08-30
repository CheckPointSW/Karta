from utils          import *
from match_library  import startMatch
from libs           import lib_factory

import ida_api as ida

####################
## Global Configs ##
####################

PROGRAM_NAME = '.'.join((ida.GetInputFile().split(os.path.sep))[-1].split('.')[:-1])
LIB_IDENTIFIER_FILE = "%s_libraries.txt" % (PROGRAM_NAME)

######################
## Global Variables ##
######################

workdir_path        = None      # path to the working directory (including the databases with the pre-compiled libraries)

all_bin_strings     = None      # list of all of the binary strings in the *.idb

logger              = None      # elementals logger instance

def writeLine(fd, line):
    """Writes the result line to the file and the log simultaneously

    Args:
        fd (fd): fd for the results file
        line (str): text line to be written to both outputs
    """
    fd.write(line + '\n')
    logger.info(line)

def writeHeader(fd):
    """Writes the header of the output file

    Args:
        fd (fd): fd for the results file
    """
    header_template = "%s Identifier - %s:"
    writeLine(fd, header_template % (LIBRARY_NAME, PROGRAM_NAME))
    writeLine(fd, '=' * (len(header_template) + len(PROGRAM_NAME) - 2))
    writeLine(fd, '')

def writeSuffix(fd):
    """Writes the SUFFIX of the output file

    Args:
        fd (fd): fd for the results file
    """
    writeLine(fd, "Final Note - Karta")
    writeLine(fd, "------------------")
    writeLine(fd, "If you encountered any bug, or wanted to add a new extension / feature, don't hesitate to contact us on GitHub.")

def identifyLibraries():
    """Iterates over the supported libraries, and activates each of them"""
    libraries_factory = lib_factory.getLibFactory()
    missing_libs = []

    # open the result file
    result_file = os.path.join(workdir_path, LIB_IDENTIFIER_FILE)
    fd = open(result_file, 'w')

    # Write the header
    logger.info('')
    writeHeader(fd)

    # We start with the matched open sources
    current_header = "Identified Open Sources:"
    writeLine(fd, current_header)
    writeLine(fd, '-' * len(current_header))

    started_closed_sources = False
    for lib_name in libraries_factory:
        # create the instance
        lib_instance = libraries_factory[lib_name](all_bin_strings)
        # check if we started the closed sources
        if not lib_instance.openSource() and not started_closed_sources:
            started_closed_sources = True
            current_header = "Identified Closed Sources:"
            writeLine(fd, '')
            writeLine(fd, current_header)
            writeLine(fd, '-' * len(current_header))
        # search for it
        match_counter = lib_instance.searchLib(logger)
        # make sure we have a single match
        if match_counter > 1:
            missing_libs.append((lib_name, lib_instance.openSource(), "Found multiple instances"))
        elif match_counter == 0:
            missing_libs.append((lib_name, lib_instance.openSource(), "Was not found"))
        # exact, single match
        else:
            # identify it's version
            lib_version = lib_instance.identifyVersion(logger)
            writeLine(fd, '%s: %s' % (lib_name, lib_version))

    # Write the missing ones too
    writeLine(fd, '')
    current_header = "Missing Open Sources:"
    writeLine(fd, current_header)
    writeLine(fd, '-' * len(current_header))

    started_closed_sources = False
    for lib_name, is_open, reason in missing_libs :
        # check if we started the closed sources
        if not is_open and not started_closed_sources:
            started_closed_sources = True
            current_header = "Missing Closed Sources:"
            writeLine(fd, '')
            writeLine(fd, current_header)
            writeLine(fd, '-' * len(current_header))
        # Now log the record
        writeLine(fd, '%s: %s' % (lib_name, reason))

    # Write the suffix
    writeLine(fd, '')
    writeSuffix(fd)

    # notify the user about the result file too
    logger.info('')
    logger.info("Wrote the results to file: %s", result_file)

def pluginMain(state_path):
    """Main function for the Karta (identifier) plugin

    Args:
        state_path (str): path to the stored state files
    """
    global logger, all_bin_strings, workdir_path

    # store it for future use
    workdir_path = state_path

    logger = Logger(LIBRARY_NAME, [], use_stdout = False, min_log_level = logging.INFO)
    logger.linkHandler(ida.IdaLogHandler())
    logger.info("Started the Script")

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")
    all_bin_strings = ida.stringList()

    # Start identifying the libraries
    logger.info("Going to identify the open (and closed) source libraries")
    identifyLibraries()

    # Finished successfully
    logger.info("Finished Successfully")

# Start to analyze the file
pluginMain('/home/eyalitki/Documents/Tools/Karta/Karta')
