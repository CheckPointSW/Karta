#!/usr/bin/python

from ar_parser             import getArchiveFiles
from config.utils          import *
from elementals            import Prompter, ProgressBar
from disassembler.factory  import identifyDisassemblerHandler
from function_context      import SourceContext, BinaryContext, IslandContext
import config.anchor           as anchor

import os
import sys
import argparse
import logging

####################
## Global Configs ##
####################

PROGRESS_BAR_THRESHOLD = 25

######################
## Global Variables ##
######################

disas_cmd = None  # Global disassembler command-line handler

def locateFiles(bin_dir, file_list, suffix):
    """Locate the inner path of the compiled (*.o / *.obj) files.

    Args:
        bin_dir (str): path to the binary folder containing the compiled files
        file_list (list): list of *.o file names (None if has no filter list)
        suffix (str): suffix for the binary files ("obj" or "o")

    Return Value:
        Generator for a tuples of the form: (abs_path, compiled_file file name)
    """
    for root, dirs, files in os.walk(bin_dir):
        if file_list is not None:
            for compiled_file in set(files).intersection(file_list):
                yield os.path.abspath(os.path.join(root, compiled_file)), compiled_file
                file_list.remove(compiled_file)
        else:
            for file in filter(lambda x: x.endswith("." + suffix), files):
                yield os.path.abspath(os.path.join(root, file)), file

def analyzeFile(full_file_path, is_windows):
    """Analyze a single file using analyzer script.

    Args:
        full_file_path (str): full path to the specific (*.obj / *.o) file
        is_windows (bool): True iff a windows compilation (*.obj or *.o)
    """
    database_path = disas_cmd.createDatabase(full_file_path, is_windows)
    disas_cmd.executeScript(database_path, SCRIPT_PATH)

def resolveUnknowns():
    """Resolve "unknown" references between the different compiled files."""
    global src_functions_ctx

    for src_func_index, src_func_ctx in enumerate(src_functions_ctx):
        for resolved_call in src_func_ctx.unknown_funcs.intersection(src_functions_list):
            src_func_ctx.recordCall(resolved_call)
            src_func_ctx.unknown_funcs.remove(resolved_call)
        for resolved_call in src_func_ctx.unknown_fptrs.intersection(src_functions_list):
            src_func_ctx.recordCall(resolved_call)
        src_func_ctx.unknown_fptrs.clear()

def analyzeLibrary(config_name, bin_dirs, compiled_ars, prompter):
    """Analyze the open source library, file-by-file and merge the results.

    Args:
        config_name (str): name of the final JSON config file
        bin_dirs (list): list of paths to the binary folders containing the compiled *.o files
        compiled_ars (list): list of paths to the compiled *.ar files
        prompter (prompter): prompter instance
    """
    prompter.info("Starting to analyze the library")
    prompter.addIndent()
    ignore_archive = len(compiled_ars) == 0
    finished_scan = False

    # workaround the enumerate in the next loop
    if ignore_archive:
        compiled_ars = range(len(bin_dirs))

    # ida has severe bugs, make sure to warn the user in advance
    if disas_cmd.name() == "IDA" and ' ' in SCRIPT_PATH:
        prompter.error("IDA does not support spaces (' ') in the script's path. Please move %s's directory accordingly (I feel your pain)", (LIBRARY_NAME))
        prompter.removeIndent()
        return

    # We could have 2 iteration rounds here
    while not finished_scan:
        # Prepare & load the stats from each file
        for index, compiled_ar in enumerate(compiled_ars):
            # check if this is a windows archive
            is_windows = isWindows()
            bin_dir = bin_dirs[index]
            bin_suffix = "o" if not is_windows else "obj"
            if not ignore_archive:
                prompter.info("Analyzing each of the files in the archive - %s", compiled_ar)
            else:
                prompter.info("Analyzing each of the *.%s files in the bin directory" % (bin_suffix))
            prompter.addIndent()
            archive_files = list(locateFiles(bin_dir, filter(lambda x: x.endswith("." + bin_suffix), getArchiveFiles(compiled_ar)) if not ignore_archive else None, bin_suffix))
            # check if we need a progress bar
            if len(archive_files) >= PROGRESS_BAR_THRESHOLD and prompter._min_level > logging.DEBUG:
                progress_bar = ProgressBar('Analyzed %d/%d files - %d%% Completed', len(archive_files), 20, True, time_format="Elapsed %M:%S -")
                progress_bar.start()
            else:
                progress_bar = None
            # start the work itself
            for full_file_path, compiled_file in archive_files:
                # ida has severe bugs, make sure to warn the user in advance
                if disas_cmd.name() == "IDA" and ' ' in full_file_path:
                    prompter.error("IDA does not support spaces (' ') in the file's path (in script mode). Please move the binary directory accordingly (I feel your pain)")
                    prompter.removeIndent()
                    return
                prompter.debug("%s - %s", full_file_path, compiled_file)
                if progress_bar is None:
                    prompter.info("%s - %s", compiled_file, full_file_path)
                # analyze the file
                analyzeFile(full_file_path, is_windows)
                # load the JSON data from it
                try:
                    fd = open(full_file_path + STATE_FILE_SUFFIX, 'r')
                except IOError:
                    prompter.error("Failed to create the .JSON file for file: %s" % (compiled_file))
                    prompter.error("Read the log file for more information: %s" % (constructLogPath(full_file_path)))
                    prompter.removeIndent()
                    prompter.removeIndent()
                    prompter.error("Encountered an error, exiting")
                    exit(1)
                # all was OK, can continue
                parseFileStats(full_file_path, json.load(fd, object_pairs_hook=collections.OrderedDict))
                fd.close()
                if progress_bar is not None:
                    progress_bar.advance(1)
            # wrap it up
            if progress_bar is not None:
                progress_bar.finish()
            prompter.removeIndent()

        # Resolve several unknowns refs as code refs
        prompter.info("Resolving cross-references between different files")
        resolveUnknowns()

        # check if we have any files in the list
        if len(src_file_mappings) == 0 and not ignore_archive:
            prompter.error("No files found in the archive :(")
            prompter.removeIndent()
            new_path = prompter.input("Do you want to analyze all of the *.%s files in the bin directory? <Y/N>: " % (bin_suffix)).lower()
            if new_path != 'y':
                prompter.error("Finished with errors!")
                exit(2)
            # run again, and ignore the archive this time
            ignore_archive = True
            prompter.addIndent()
        else:
            finished_scan = True

    # Remove empty files
    prompter.info("Filtering out empty files")
    for file_name in filter(lambda x: len(src_file_mappings[x]) == 0, src_file_mappings):
        src_file_mappings.pop(file_name)

    # Create the list of anchors
    str_anchors   = []
    const_anchors = []
    anchors_list  = []
    anchors_files = set()
    prompter.info("Identifying possible Anchor functions")
    prompter.addIndent()
    seen_strings, seen_consts, function_list = getContextsStats()
    for src_func_index, src_func_ctx in enumerate(src_functions_ctx):
        is_str, threshold, candidates = anchor.isAnchor(src_func_ctx, seen_strings, seen_consts, function_list, prompter)
        if candidates is None:
            continue
        if is_str:
            str_anchors.append(src_func_index)
        else:
            const_anchors.append(src_func_index)
        anchors_files.add(src_func_ctx.file)
    prompter.removeIndent()

    # strings before const, because they are faster to search for
    anchors_list = str_anchors + const_anchors

    # check if we have any files left
    if len(src_file_mappings) == 0:
        prompter.error("All files were empty :(")
        prompter.removeIndent()
        prompter.error("Finished with errors!")
        exit(2)

    # Check for an error
    if len(anchors_list) == 0:
        prompter.warning("Failed to find Anchor functions in the library :(")
        prompter.warning("You should define manual anchors instead")

    # Create the anchors file
    prompter.info("Generating the full JSON file: %s", config_name)
    prompter.addIndent()
    full_json = {}

    # Serialize the anchor list
    prompter.info("Writing the anchor list")
    full_json[JSON_TAG_ANCHORS] = anchors_list

    # Serialize the functions of each files
    prompter.info("Writing the function list for each of the files")
    file_dict = collections.OrderedDict()
    # find a common file prefix, and remove it form the file path
    if len(src_file_mappings) > 1:
        base_value = src_file_mappings.keys()[0].split(os.path.sep)
        comparison_value = src_file_mappings.keys()[-1].split(os.path.sep)
        for index in xrange(min(len(comparison_value), len(base_value))):
            if base_value[index] != comparison_value[index]:
                break
        common_path_len = len(os.path.sep.join(base_value[:index])) + 1
    else:
        common_path_len = len(bin_dirs[0]) + 1

    for src_file_name in src_file_mappings:
        file_dict[src_file_name[common_path_len:]] = map(lambda c: c.serialize(), src_file_mappings[src_file_name])
    full_json[JSON_TAG_FILES] = file_dict

    # actually dump it
    fd = open(config_name, "w")
    json.dump(full_json, fd)
    fd.close()
    prompter.removeIndent()

    prompter.info("Anchor to file ratio is: %d/%d", len(anchors_files), len(src_file_mappings))
    prompter.info("Anchor to function ratio is: %d/%d", len(anchors_list), len(src_functions_list))
    prompter.removeIndent()

def main(args):
    """Create a .json configuration for the open source library version.

    Args:
        args (list): list of command line arguments
    """
    global disas_cmd

    # argument parser
    parser = argparse.ArgumentParser(description='Compiles a *.json configuration file for a specific version of an open source library, later to be used by %s\'s Matcher.' % (LIBRARY_NAME))
    parser.add_argument('name', metavar='lib-name', type=str,
                        help='name (case sensitive) of the open source library')
    parser.add_argument('version', metavar='lib-version', type=str,
                        help='version string (case sensitive) as used by the identifier')
    parser.add_argument('couples', metavar='dir archive', type=str, nargs='+',
                        help='directory with the compiled *.o / *.obj files + path to the matching *.a / *.lib file (if didn\'t use "--no-archive")')
    parser.add_argument('-D', '--debug', action='store_true', help='set logging level to logging.DEBUG')
    parser.add_argument('-N', '--no-archive', action='store_false', help='extract data from all *.o / *.obj files in the directory')
    parser.add_argument('-W', '--windows', action='store_true', help='signals that the binary was compiled for Windows')

    # parse the args
    args = parser.parse_args(args)
    library_name    = args.name
    library_version = args.version
    is_debug        = args.debug
    is_windows      = args.windows
    using_archives  = args.no_archive
    couples         = args.couples

    bin_dirs      = []
    archive_paths = []
    if using_archives:
        if len(couples) % 2 != 0:
            parser.error("Odd length in list of dir,archive couples, should be: [(directory, archive name), ...]")
        for i in xrange(0, len(couples), 2):
            bin_dirs.append(couples[i])
            archive_paths.append(couples[i + 1])
    else:
        bin_dirs = couples

    # open the log
    prompter = Prompter(min_log_level=logging.INFO if not is_debug else logging.DEBUG)
    prompter.info('Starting the Script')

    # requesting the path to the chosen disassembler
    setDisassemblerPath(prompter)
    disas_cmd = identifyDisassemblerHandler(getDisasPath(), prompter)
    if disas_cmd is None:
        return

    # register our contexts
    registerContexts(SourceContext, BinaryContext, IslandContext)

    # use the user supplied flag
    if is_windows:
        setWindowsMode()

    # Check if launched from the src directory
    if not os.path.exists(SCRIPT_PATH):
        prompter.error('The script should be executed from Karta\'s src directory!')
        prompter.error('Exiting')
        return

    # analyze the open source library
    analyzeLibrary(constructConfigPath(library_name, library_version), bin_dirs, archive_paths, prompter)

    # finished
    prompter.info('Finished Successfully')


if __name__ == "__main__":
    main(sys.argv[1:])
