import sark
import idc
import logging
from elementals                 import Logger
from analyzer_utils             import *
from analyzers.analyzer_factory import createAnalyzer

##
# Taken from Karta :)
##
class IdaLogHandler(logging.Handler):
    """Integrate the log messages with IDA's output window."""

    def emit(self, record):
        """Emit a log record into IDA's output window.

        Args:
            record (LogRecord): a logging.LogRecord instance
        """
        idc.msg("%s\n" % (super(IdaLogHandler, self).format(record)))

def analysisStart(analyzer, scs, sds):
    """Start all of the analysis steps for the binary.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments
        sds (list): list of (sark) data segments

    Return Value:
        True iff the analysis was finished successfully
    """
    phase_counter = 1

    #####################
    # 1. Clean the code #
    #####################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Tell IDA to analyze all of the code segments")
    cleanStart(analyzer, scs)
    idaapi.auto_wait()

    ##############################################
    # 2. Observe and Locate the program features #
    ##############################################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Observe all code patterns from the initial analysis")
    if not gatherIntel(analyzer, scs, sds):
        analyzer.logger.error("Failed during intelligence gathering, exiting")
        return False
    if analyzer.isCodeContainsData():
        analyzer.logger.info("Locate all global strings")
        analyzer.str_identifier.locateDataStrings(sds)
        analyzer.logger.info("Locate all global data / function pointers")
        analyzer.fptr_identifier.locateDataPtrs(scs, sds)
    analyzer.logger.info("Locate all switch tables")
    if analyzer.switch_identifier.observeSwitchTableFeatures(scs):
        analyzer.switch_identifier.locateSwitchTables(scs)
    else:
        analyzer.logger.error("Failed in finding a switch table pattern")
    idaapi.auto_wait()

    ##########################
    # 3. Re-Analyze the code #
    ##########################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Tell IDA to re-analyze all of the code segments, using the added features")
    cleanStart(analyzer, scs, undef=True)
    idaapi.auto_wait()

    ####################################
    # 4. Start handling the code types #
    ####################################

    if analyzer.hasActiveCodeTypes():
        analyzer.logger.info(f"Phase #{phase_counter}")
        phase_counter += 1
        analyzer.logger.info("Observe all code patterns from the improved analysis")
        if not gatherIntel(analyzer, scs, sds):
            analyzer.logger.error("Failed during intelligence gathering, exiting")
            return False
        analyzer.logger.info("Help IDA figure out the transition point between the different code types")
        # easy phase
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=False)
        idaapi.auto_wait()
        # aggressive phase
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=True)

    ##########################
    # 5. Re-Analyze the code #
    ##########################

    if analyzer.hasActiveCodeTypes():
        analyzer.logger.info(f"Phase #{phase_counter}")
        phase_counter += 1
        analyzer.logger.info("Tell IDA to re-analyze all of the code segments, using the added features")
        num_false_fptrs = -1
        while num_false_fptrs != 0:
            cleanStart(analyzer, scs, undef=True)
            # Remove false fptrs
            num_false_fptrs = analyzer.fptr_identifier.checkPointedFunctions()
            analyzer.logger.info(f"Removed {num_false_fptrs} possibly wrong fptrs")

    ###########################
    # 6. Define the functions #
    ###########################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Observe all code patterns from the improved analysis")
    if not gatherIntel(analyzer, scs, sds):
        analyzer.logger.error("Failed during intelligence gathering, exiting")
        return False
    analyzer.logger.info("Start marking functions, even without xrefs")
    functionScan(analyzer, scs)

    #####################################
    # 7. Finish handling the code types #
    #####################################

    if analyzer.hasActiveCodeTypes():
        analyzer.logger.info(f"Phase #{phase_counter}")
        phase_counter += 1
        analyzer.logger.info("Aggressively help IDA figure out the transition point between the different code types")
        # Find code type transitions, and resolve the complex ones
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=True)
        # Check if we can expand the transitions backward
        for sc in scs:
            negotiateRegions(analyzer, sc)
        # Find code type transitions, and resolve the complex ones
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=True, align=True)
        # Make sure no one destroyed a switch table
        for sc in scs:
            analyzer.switch_identifier.markSwitchTables(sc)

    #####################################
    # 8. Finish defining data constants #
    #####################################

    if analyzer.isCodeContainsData() and not analyzer.isCodeMixedWithData():
        analyzer.logger.info(f"Phase #{phase_counter}")
        phase_counter += 1
        analyzer.logger.info("Locate all in-code constants & strings")
        analyzer.locals_identifier.locateLocalConstants(scs, sds)
        for sc in scs:
            analyzer.switch_identifier.markSwitchTables(sc, aggressive=False)
        analyzer.logger.info("Fixup isolated data chunks")
        dataScan(analyzer, scs)

    ####################################
    # 9. Finish defining the functions #
    ####################################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Aggressively scan for functions")
    functionScan(analyzer, scs)
    # Declare functions from every code that left after the "conservative" scan
    aggressiveFunctionScan(analyzer, scs)

    ###############################
    # 10. Resolve function chunks #
    ###############################

    analyzer.logger.info(f"Phase #{phase_counter}")
    phase_counter += 1
    analyzer.logger.info("Resolve all function chunks")
    resolveFunctionChunks(analyzer, scs)

    # If reached thus far, all was OK
    return True

def main():
    """Start Thumbs Up IDA plugin - Firmware version."""
    # Init the logger
    logger = Logger("Thumbs Up Logger", [("thumbs_up.log", "w", logging.INFO)], use_stdout=False, min_log_level=logging.INFO)
    logger.linkHandler(IdaLogHandler())
    # Locate the segments
    code_segments = [sc for sc in sark.segments() if sc.type == 2]
    data_segments = [sc for sc in sark.segments() if sc.type in [0, 3]]
    # Sanity checks
    if len(code_segments) == 0:
        logger.error("Failed to find any code segment, can't continue...")
        return
    if len(data_segments) == 0:
        logger.error("Failed to find any data segment, can't continue...")
        return
    # Notify the user about our segment decisions
    logger.info("Segments, as marked by the disassembler:")
    for sc in code_segments:
        logger.info(f"Code Segment: 0x{sc.start_ea:x} - 0x{sc.end_ea:x}")
    for sd in data_segments:
        logger.info(f"Data Segment: 0x{sd.start_ea:x} - 0x{sd.end_ea:x}")

    # Build up the analyzer
    analyzer = createAnalyzer(logger, False)
    # Sanity check
    if analyzer is None:
        logger.error("Exiting")
        return
    # Finish building the analyzer
    analyzer.linkFunctionClassifier()
    analyzer.linkFptrIdentifier()
    analyzer.linkStringIdentifier()
    analyzer.linkLocalsIdentifier()
    analyzer.linkSwitchIdentifier()

    # Notify the user about the code types
    analyzer.presentCodeTypes()

    # Start the analysis
    logger.info("Starting the analysis")
    result = analysisStart(analyzer, code_segments, data_segments)
    if result:
        logger.info("Successfully finished the analysis")
    else:
        logger.error("Encountered an error during the analysis")


# Invoke the main function
main()
