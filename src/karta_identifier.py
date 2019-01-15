from config.utils           import *
from disassembler.factory   import createDisassemblerHandler
from libs                   import lib_factory

from elementals import Logger
import logging

####################
## Global Configs ##
####################

LIB_IDENTIFIER_FORMAT = "%s_libraries.txt"

######################
## Global Variables ##
######################

workdir_path        = None      # path to the working directory (including the databases with the pre-compiled libraries)
logger              = None      # elementals logger instance
disas               = None      # disassembler layer handler

def writeLine(fd, line):
    """Write the result line to the file and the log simultaneously.

    Args:
        fd (fd): fd for the results file
        line (str): text line to be written to both outputs
    """
    fd.write(line + '\n')
    logger.info(line)

def writeHeader(fd):
    """Write the header of the output file.

    Args:
        fd (fd): fd for the results file
    """
    header_template = "%s Identifier - %s:"
    program_name = disas.inputFile()
    writeLine(fd, header_template % (LIBRARY_NAME, program_name))
    writeLine(fd, '=' * (len(header_template) + len(LIBRARY_NAME) + len(program_name) - 4))
    writeLine(fd, '')

def writeSuffix(fd):
    """Write the SUFFIX of the output file.

    Args:
        fd (fd): fd for the results file
    """
    writeLine(fd, "Final Note - %s" % (LIBRARY_NAME))
    writeLine(fd, "-------------%s" % ('-' * len(LIBRARY_NAME)))
    writeLine(fd, "If you encountered any bug, or wanted to add a new extension / feature, don't hesitate to contact us on GitHub:")
    writeLine(fd, "https://github.com/CheckPointSW/Karta")

def identifyLibraries():
    """Iterate over the supported libraries, and activates each of them."""
    libraries_factory = lib_factory.getLibFactory()
    missing_libs = []

    # open the result file
    result_file = LIB_IDENTIFIER_FORMAT % (disas.databaseFile())
    fd = open(result_file, 'w')

    # Write the header
    logger.info('')
    writeHeader(fd)

    # Load the accumulated knowledge for this binary file
    knowledge_config = loadKnowledge()
    if knowledge_config is not None and JSON_TAG_MANUAL_VERSIONS in knowledge_config:
        all_manual_versions = knowledge_config[JSON_TAG_MANUAL_VERSIONS]
    else:
        all_manual_versions = []
        logger.debug("Has no manual versions")

    # We start with the matched open sources
    current_header = "Identified Open Sources:"
    writeLine(fd, current_header)
    writeLine(fd, '-' * len(current_header))

    started_closed_sources = False
    num_listed = 0
    for lib_name in libraries_factory:
        # check for a pre-supplied manual version
        if lib_name in all_manual_versions:
            manual_versions = all_manual_versions[lib_name]
            logger.debug("Manual versions: %s", ", ".join(manual_versions))
        else:
            manual_versions = []
        # create the instance
        lib_instance = libraries_factory[lib_name](disas.strings())
        # check if we started the closed sources
        if not lib_instance.openSource() and not started_closed_sources:
            # pretty print the empty list too
            if num_listed == 0:
                writeLine(fd, "(none)")
            started_closed_sources = True
            current_header = "Identified Closed Sources:"
            writeLine(fd, '')
            writeLine(fd, current_header)
            writeLine(fd, '-' * len(current_header))
            num_listed = 0
        # search for it
        match_counter = lib_instance.searchLib(logger)
        # make sure we have a single match
        if match_counter == 0:
            missing_libs.append((lib_name, lib_instance.openSource(), "Was not found"))
        # found at least one version
        else:
            # identify the version
            lib_versions = lib_instance.identifyVersions(logger)
            # check if we can solve some unknowns
            if lib_instance.VERSION_UNKNOWN in lib_versions:
                # remove the intersection with the manual versions
                agreed_versions = set(lib_versions).intersection(manual_versions)
                conflicting_versions = list(set(lib_versions).difference(manual_versions))
                useful_versions = list(set(manual_versions).difference(agreed_versions))
                # check for an exact match
                if len(conflicting_versions) == 1 and len(useful_versions) == 1:
                    # unfortunately python's list has no "replace" method...
                    lib_versions = list(agreed_versions) + useful_versions
            writeLine(fd, '%s: %s' % (lib_name, ', '.join(lib_versions)))
            num_listed += 1

    # pretty print the empty list too
    if num_listed == 0:
        writeLine(fd, "(none)")
    # Write the missing ones too
    writeLine(fd, '')
    current_header = "Missing Open Sources:"
    writeLine(fd, current_header)
    writeLine(fd, '-' * len(current_header))

    started_closed_sources = False
    for lib_name, is_open, reason in missing_libs:
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
    # And now with GUI
    disas.messageBox("Results were saved to file: %s" % (result_file))

def pluginMain():
    """Run the Karta (identifier) plugin."""
    global logger, disas

    logger = Logger(LIBRARY_NAME, [], use_stdout=False, min_log_level=logging.INFO)
    initUtils(logger, createDisassemblerHandler(logger))
    disas = getDisas()
    logger.info("Started the Script")

    # Init the strings list (Only once, because it's heavy to calculate)
    logger.info("Building a list of all of the strings in the binary")

    # Start identifying the libraries
    logger.info("Going to identify the open (and closed) source libraries")
    identifyLibraries()

    # Finished successfully
    logger.info("Finished Successfully")


# Start to analyze the file
pluginMain()
