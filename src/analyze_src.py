from ar_parser  import getArchiveFiles
from utils      import *
from elementals import Prompter

import os
import sys

def locateFiles(bin_dir, file_list) :
    """Locates the inner path of the compiled *.o files

    Args:
        bin_dir (str): path to the binary folder containing the compiled *.o file
        file_list (list): list of *.o file names

    Return Value:
        Generator for a tuples of the form: (abs_path, compiled_file file name)
    """

    for root, dirs, files in os.walk(bin_dir) :
        for compiled_file in set(files).intersection(file_list) :
            yield os.path.abspath(os.path.join(root, compiled_file)), compiled_file

def analyzeFile(full_file_path) :
    """Analyze a single file using IDA Python
    
    Args:
        full_file_path (str): full path to the specific *.o file
    """
    os.system(IDA_PATH + " -A -B -Telf '%s'" % (full_file_path))
    os.system(IDA_PATH + " -A -Telf -S'%s' '%s'" % (SCRIPT_PATH, full_file_path + ".idb"))

def resolveUnknowns() :
    """Resolves "unknown" references between the different compiled files"""
    global src_functions_ctx

    for src_func_index, src_func_ctx in enumerate(src_functions_ctx) :
        for resolved_call in src_func_ctx._unknowns.intersection(src_functions_list) :
            src_func_ctx.recordCall(resolved_call)
            src_func_ctx._unknowns.remove(resolved_call)

def analyzeLibrary(config_name, bin_dirs, compiled_ars, logger) :
    """Analyze of the open source library, file-by-file and merge the results
    
    Args:
        config_name (str): name of the final JSON config file
        bin_dirs (list): list of paths to the binary folders containing the compiled *.o files
        compiled_ars (list): list of paths to the compiled *.ar files
        logger (logger): logger instance
    """

    logger.info("Starting to analyze the library")
    logger.addIndent()

    # Prepare & load the stats from each file
    for index, compiled_ar in enumerate(compiled_ars) :
        bin_dir = bin_dirs[index]
        logger.info("Analyze each of the files in the archive - %s", compiled_ar)
        logger.addIndent()
        for full_file_path, compiled_file in locateFiles(bin_dir, getArchiveFiles(compiled_ar)) :
            logger.info("%s - %s", compiled_file, full_file_path)
            # analyze the file
            analyzeFile(full_file_path)
            # load the JSON data from it
            fd = open(full_file_path + STATE_FILE_SUFFIX, 'r')
            parseFileStats(full_file_path, json.load(fd, object_pairs_hook=collections.OrderedDict))
            fd.close()
        logger.removeIndent()

    # Resolve several unknowns refs as code refs
    logger.info("Resolve cross-references between different files")
    resolveUnknowns()

    # Remove empty files
    logger.info("Filter out empty files")
    for file_name in filter(lambda x : len(src_file_mappings[x]) == 0, src_file_mappings) :
        src_file_mappings.pop(file_name)

    # Create the list of anchors
    str_anchors   = []
    const_anchors = []
    anchors_list  = []
    anchors_files = set()
    logger.info("Identifying possible Anchor functions")
    logger.addIndent()
    for src_func_index, src_func_ctx in enumerate(src_functions_ctx) :
        is_str, threshold, candidates = isAnchor(src_func_ctx, logger)
        if candidates is None :
            continue
        if is_str :
            str_anchors.append(src_func_index)
        else :
            const_anchors.append(src_func_index)
        anchors_files.add(src_func_ctx._file)
    logger.removeIndent()

    # strings before const, because they are faster to search for
    anchors_list = str_anchors + const_anchors

    # Check for an error
    if len(anchors_list) == 0:
        logger.error("Failed to find Anchor functions in the library :(")
        logger.removeIndent()
        logger.error("Finished with errors!")
        exit(2)

    # Create the anchors file
    logger.info("Generating the full JSON file: %s", config_name)
    logger.addIndent()
    full_json = {}

    # Serialize the anchor list
    logger.info("Writing the anchor list")
    full_json['Anchors (Src Index)'] = anchors_list

    # Serialize the functions of each files
    logger.info("Writing the function list for each of the files")
    file_dict = collections.OrderedDict()
    # find a common file prefix, and remove it form the file path
    if len(src_file_mappings) > 1 :
        base_value = src_file_mappings.keys()[0].split(os.path.sep)
        comparison_value = src_file_mappings.keys()[-1].split(os.path.sep)
        for index in xrange(min(len(comparison_value), len(base_value))) :
            if base_value[index] != comparison_value[index] :
                break
        common_path_len = len(os.path.sep.join(base_value[:index])) + 1
    else :
        common_path_len = len(bin_dirs[0])

    for src_file_name in src_file_mappings :
        file_dict[src_file_name[common_path_len:]] = map(lambda c : c.serialize(), src_file_mappings[src_file_name])
    full_json['Files'] = file_dict

    # actually dump it
    fd = open(config_name, "w")
    json.dump(full_json, fd)
    fd.close()
    logger.removeIndent()

    logger.info("Anchor to file ratio is: %d/%d", len(anchors_files), len(src_file_mappings))
    logger.info("Anchor to function ratio is: %d/%d", len(anchors_list), len(src_functions_list))
    logger.removeIndent()

def printUsage(args):
    """Prints usage instructions for this file
    
    Args:
        args (list): list of cmd line arguments
    """
    print 'Usage: %s <library name> <library version> <bin dir> <.ar compiled archive>' % (args[0])
    print 'Exitting'
    exit(1)

def main(args):
    # Check the arguments
    if len(args) < 1 + 4 or (len(args) - 3) % 2 != 0:
        print 'Wrong amount of arguments, got %d, expected %d' % (len(args) - 1, 4)
        printUsage( args )
        
    # parse the args
    library_name    = args[1]
    library_version = args[2]
    bin_dirs      = []
    archive_paths = []
    for i in xrange(3, len(args), 2) :
        bin_dirs.append(args[i])
        archive_paths.append(args[i + 1])

    # open the log
    prompter = Prompter()
    prompter.info('Starting the Script')

    # analyze the open source library
    analyzeLibrary(constructConfigPath(library_name, library_version), bin_dirs, archive_paths, prompter)

    # finished
    prompter.info('Finished Successfully')

if __name__ == "__main__":
    main(sys.argv)
