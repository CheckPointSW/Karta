from ida_utils  import *
from elementals import Logger
import time

def analyzeFile() :
    """Analyzes all of the (source) functions for a single compiled file"""
    # create a logger
    logger = Logger(LIBRARY_NAME, use_stdout = False, min_log_level = logging.INFO)
    logger.linkHandler(ida.IdaLogHandler())
    logger.info("Started the Script")
    # TODO: create a database
    contexts = []
    extern_seg = ida.get_segm_by_name("extern")
    # build the list of exported (non-static) functions
    exported = map(lambda x : x[-1], ida.Entries())
    for func_ea in list(Functions()) :
        # skip imported functions
        if extern_seg is not None and extern_seg.start_ea <= func_ea and func_ea < extern_seg.end_ea :
            continue
        src_ctx = analyzeFunction(func_ea, True)
        # check if static or not
        if src_ctx._name not in exported :
            src_ctx.markStatic()
        contexts.append(src_ctx)
    functionsToFile(GetInputFile(), contexts)
    logger.info("Finished Successfully")

# Always init the utils before we start
initUtils()
# Start to analyze the file
analyzeFile()
# Exit IDA
Exit(0)
