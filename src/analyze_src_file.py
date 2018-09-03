from ida_utils  import *
from elementals import Logger

def analyzeFile() :
    """Analyzes all of the (source) functions for a single compiled file"""
    # create a logger
    logger = Logger(LIBRARY_NAME, use_stdout = False, min_log_level = logging.INFO)
    logger.linkHandler(IdaLogHandler())
    logger.info("Started the Script")
    contexts = []
    # build the list of exported (non-static) functions
    exported = map(lambda x : x[-1], idautils.Entries())
    for segment_idx in xrange(len(list(Segments()))) :
        if ".text" not in sark.Segment(index = segment_idx).name:
            continue
        for function in sark.Segment(index = segment_idx).functions :
            src_ctx = analyzeFunction(function.ea, True)
            # check if static or not
            if src_ctx._name not in exported :
                src_ctx.markStatic()
            contexts.append(src_ctx)
    functionsToFile(idc.GetInputFile(), contexts)
    logger.info("Finished Successfully")

# Always init the utils before we start
initUtils()
# Start to analyze the file
analyzeFile()
# Exit IDA
Exit(0)
