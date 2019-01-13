#!/usr/bin/python

from config.utils          import *
from elementals            import Prompter

import sys
import argparse
import logging
from collections import defaultdict
from libs        import lib_factory

def recordManualVersions(knowledge_config, prompter):
    """Record the list of user defined manual library versions.

    Args:
        knowledge_config (dict): a mapping of all of the accumulated knowledge for the currently analysed binary
        prompter (prompter): prompter instance

    Return Value:
        Updated knowledge mapping (to be stored back as a *json file)
    """
    # Load the information we have on the supported libraries
    libraries_factory = lib_factory.getLibFactory()
    # Start requesting the user to add his manual records
    manual_versions = defaultdict(list)
    prompter.info("Starting the input loop")
    prompter.addIndent()
    finished = False
    while not finished:
        prompter.info("Enter the details for the current manually identified library:")
        parsed_correctly = True
        while parsed_correctly:
            lib_name = prompter.input("Library Name (case sensitive): ")
            # check existence
            if lib_name not in libraries_factory:
                prompter.error("Library \"%s\" does not exist", lib_name)
                parsed_correctly = False
                break
            # get the manual version
            manual_version = prompter.input("Library Version (case sensitive): ")
            # finished successfully :)
            manual_versions[lib_name].append(manual_version)
            break

        should_continue = prompter.input("Do you want to identify another library version? <Y/N>: ")
        finished = should_continue.lower() != 'y'
    prompter.removeIndent()

    # add the info to the json
    if len(manual_versions) > 0:
        if JSON_TAG_MANUAL_VERSIONS not in knowledge_config:
            knowledge_config[JSON_TAG_MANUAL_VERSIONS] = {}
        all_manual_versions = knowledge_config[JSON_TAG_MANUAL_VERSIONS]
        for lib_name in manual_versions:
            if lib_name not in all_manual_versions:
                all_manual_versions[lib_name] = []
                cur_manual_versions = all_manual_versions[lib_name]
                # merge the results
                for new_version in manual_versions[lib_name]:
                    if new_version not in cur_manual_versions:
                        cur_manual_versions.append(new_version)

    # return back the data
    return knowledge_config


def main(args):
    """Run the manual library identifier script.

    Args:
        args (list): list of command line arguments
    """
    global disas_cmd

    # argument parser
    parser = argparse.ArgumentParser(description='Enables the user to manually identify the versions of located but unknown libraries, later to be used by %s\'s Matcher.' % (LIBRARY_NAME))
    parser.add_argument('bin', metavar='bin', type=str,
                        help='path to the disassembler\'s database for the wanted binary')
    parser.add_argument('-D', '--debug', action='store_true', help='set logging level to logging.DEBUG')

    # parse the args
    args = parser.parse_args(args)
    bin_path = args.bin
    is_debug = args.debug

    # open the log
    prompter = Prompter(min_log_level=logging.INFO if not is_debug else logging.DEBUG)
    prompter.info('Starting the Script')

    # always init the utils before we start
    initUtils(prompter, None, invoked_before=True)

    # Load the existing knowledge config, if exists
    prompter.debug('Opening knowledge configuration file from path: %s', accumulatedKnowledgePath(bin_path))
    prompter.addIndent()
    knowledge_config = loadKnowledge(bin_path)
    if knowledge_config is None:
        prompter.debug('Failed to find an existing configuration file')
        knowledge_config = {}
    prompter.removeIndent()

    # receive all of the couples from the user
    knowledge_config = recordManualVersions(knowledge_config, prompter)
    prompter.info('Storing the data to the knowledge configuration file')
    storeKnowledge(knowledge_config, bin_path)

    # finished
    prompter.info('Finished Successfully')


if __name__ == "__main__":
    main(sys.argv[1:])
