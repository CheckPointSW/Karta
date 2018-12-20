from config.utils           import *
from disassembler.factory   import createDisassemblerHandler
from function_context       import SourceContext, BinaryContext, IslandContext
from elementals             import Logger
import logging
import traceback

def analyzeFile():
    """Analyzes all of the (source) functions for a single compiled file."""
    disas = getDisas()
    logger.info("Started the Script")
    contexts = []
    # check for windows binary
    if disas.inputFile().endswith(".obj"):
        logger.debug("Activating Windows mode")
        setWindowsMode()
    # build the list of exported (non-static) functions
    exported = disas.exports()
    for segment_idx in xrange(disas.numSegments()):
        if ".text" not in disas.segmentName(segment_idx):
            continue
        for function_ea in disas.segmentFunctions(segment_idx):
            src_ctx = disas.analyzeFunction(function_ea, True)
            # check if static or not
            if src_ctx.name not in exported:
                src_ctx.markStatic()
            contexts.append(src_ctx)
    functionsToFile(disas.inputFile(), contexts)
    logger.info("Finished Successfully")


# create a logger
logger = Logger(LIBRARY_NAME, use_stdout=False)
# Always init the utils before we start
initUtils(logger, createDisassemblerHandler(logger))
# Register our contexts
registerContexts(SourceContext, BinaryContext, IslandContext)
# Start to analyze the file
try:
    logger.linkHandler(logging.FileHandler(constructLogPath(), "w"))
    analyzeFile()
except Exception:
    logger.error(traceback.format_exc())
# Exit the disassembler
getDisas().exit()
