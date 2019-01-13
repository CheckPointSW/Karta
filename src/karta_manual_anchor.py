#!/usr/bin/python

from config.utils          import *
from elementals            import Prompter
from function_context      import SourceContext, BinaryContext, IslandContext

import os
import sys
import argparse
import logging
from collections import defaultdict

def recordManualAnchors(library_config, knowledge_config, lib_name, prompter):
    """Record the list of user defined manual anchor matches.

    Args:
        library_config (json): json loaded data from the library's configuration
        knowledge_config (dict): a mapping of all of the accumulated knowledge for the currently analysed binary
        lib_name (str): name of the open source library that will contain these manual anchors
        prompter (prompter): prompter instance

    Return Value:
        Updated knowledge mapping (to be stored back as a *json file)
    """
    # Prepare & load the stats from each file (using the functions file)
    src_file_names = []
    prompter.info("Loading the information regarding the compiled source files")
    prompter.addIndent()
    files_config = library_config[JSON_TAG_FILES]
    for full_file_path in files_config:
        prompter.debug("Parsing the canonical representation of file: %s", full_file_path.split(os.path.sep)[-1])
        src_file_names.append(full_file_path)
        parseFileStats(full_file_path, files_config[full_file_path])
    prompter.removeIndent()

    # get the variables from the utils file
    src_functions_list, src_functions_ctx, src_file_mappings = getSourceFunctions()

    # pre-processed list indices (efficiency improvement)
    func_indices = defaultdict(list)
    for func_idx, func_name in enumerate(src_functions_list):
        func_indices[func_name].append(func_idx)

    # Start requesting the user to add his manual records
    manual_anchors = {}
    prompter.info("Starting the input loop")
    prompter.addIndent()
    finished = False
    while not finished:
        prompter.info("Enter the details for the current manual anchor:")
        parsed_correctly = True
        while parsed_correctly:
            function_name = prompter.input("Function Name (case sensitive): ")
            # check existence
            if src_functions_list.count(function_name) == 0:
                prompter.error("Function \"%s\" does not exist", function_name)
                parsed_correctly = False
                break
            # check uniqueness
            if src_functions_list.count(function_name) > 1:
                file_name = prompter.input("File Name (case sensitive): ")
                src_indices = filter(lambda x: src_functions_ctx[x].file == file_name, func_indices[function_name])
                if len(src_indices) == 0:
                    prompter.error("Function \"%s\" does not exist in file \"%s\"", file_name)
                    parsed_correctly = False
                    break
                src_index = src_indices[0]
            else:
                src_index = func_indices[function_name][0]
            # get the binary address
            bin_ea_str_raw = prompter.input("Function Address (ea in the form: 0x12345678): ")
            if bin_ea_str_raw.startswith("0x"):
                bin_ea_str = bin_ea_str_raw[2:]
            else:
                bin_ea_str = bin_ea_str_raw
            try:
                bin_ea = int(bin_ea_str, 16)
            except ValueError:
                prompter.error("Illegal hexa address: \"%s\"", bin_ea_str_raw)
                parsed_correctly = False
                break
            # finished successfully :)
            manual_anchors[src_index] = bin_ea
            break

        should_continue = prompter.input("Do you want to add another manual anchor? <Y/N>: ")
        finished = should_continue.lower() != 'y'
    prompter.removeIndent()

    # add the info to the json
    if len(manual_anchors) > 0:
        if JSON_TAG_MANUAL_ANCHORS not in knowledge_config:
            knowledge_config[JSON_TAG_MANUAL_ANCHORS] = {}
        all_manual_anchors = knowledge_config[JSON_TAG_MANUAL_ANCHORS]
        if lib_name not in all_manual_anchors:
            all_manual_anchors[lib_name] = {}
        cur_manual_anchors = all_manual_anchors[lib_name]
        # merge the results
        for new_index in manual_anchors:
            src_ctx = src_functions_ctx[new_index]
            cur_manual_anchors[str(new_index)] = [src_ctx.file, src_ctx.name, hex(manual_anchors[new_index]), manual_anchors[new_index]]

    # return back the data
    return knowledge_config


def main(args):
    """Run the manual anchors script.

    Args:
        args (list): list of command line arguments
    """
    global disas_cmd

    # argument parser
    parser = argparse.ArgumentParser(description='Enables the user to manually defined matches, acting as manual anchors, later to be used by %s\'s Matcher.' % (LIBRARY_NAME))
    parser.add_argument('bin', metavar='bin', type=str,
                        help='path to the disassembler\'s database for the wanted binary')
    parser.add_argument('name', metavar='lib-name', type=str,
                        help='name (case sensitive) of the relevant open source library')
    parser.add_argument('version', metavar='lib-version', type=str,
                        help='version string (case sensitive) as used by the identifier')
    parser.add_argument('config', metavar='configs', type=str,
                        help='path to the *.json "configs" directory')
    parser.add_argument('-D', '--debug', action='store_true', help='set logging level to logging.DEBUG')
    parser.add_argument('-W', '--windows', action='store_true', help='signals that the binary was compiled for Windows')

    # parse the args
    args = parser.parse_args(args)
    library_name    = args.name
    library_version = args.version
    bin_path        = args.bin
    config_path     = args.config
    is_debug        = args.debug
    is_windows      = args.windows

    # open the log
    prompter = Prompter(min_log_level=logging.INFO if not is_debug else logging.DEBUG)
    prompter.info('Starting the Script')

    # use the user supplied flag
    if is_windows:
        setWindowsMode()

    # always init the utils before we start
    initUtils(prompter, None, invoked_before=True)
    # register our contexts
    registerContexts(SourceContext, BinaryContext, IslandContext)

    # Load the information from the relevant library
    lib_config_file = constructConfigPath(library_name, library_version)
    prompter.debug('Loading the configuration file for library: %s', library_name)
    prompter.addIndent()
    cur_config_path = os.path.join(config_path, lib_config_file)
    if not os.path.exists(cur_config_path):
        prompter.error('Missing configuration file (%s) for \"%s\" Version: \"%s\"', lib_config_file, library_name, library_version)
        return
    # Load the configuration file
    fd = open(cur_config_path, 'r')
    library_config = json.load(fd, object_pairs_hook=collections.OrderedDict)
    fd.close()
    prompter.removeIndent()

    # Load the existing knowledge config, if exists
    prompter.debug('Opening knowledge configuration file from path: %s', accumulatedKnowledgePath(bin_path))
    prompter.addIndent()
    knowledge_config = loadKnowledge(bin_path)
    if knowledge_config is None:
        prompter.debug('Failed to find an existing configuration file')
        knowledge_config = {}
    prompter.removeIndent()

    # receive all of the couples from the user
    knowledge_config = recordManualAnchors(library_config, knowledge_config, library_name, prompter)
    prompter.info('Storing the data to the knowledge configuration file')
    storeKnowledge(knowledge_config, bin_path)

    # finished
    prompter.info('Finished Successfully')


if __name__ == "__main__":
    main(sys.argv[1:])
