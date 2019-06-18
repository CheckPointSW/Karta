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
        idc.Message("%s\n" % (super(IdaLogHandler, self).format(record)))

def analysisStart(analyzer, scs, sds):
    """Start all of the analysis steps for the binary.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments
        sds (list): list of (sark) data segments

    Return Value:
        True iff the analysis was finished successfully
    """
    has_code_types = analyzer.hasCodeTypes()
    phase_counter = 1

    #####################
    # 1. Clean the code #
    #####################

    analyzer.logger.info("Phase #%d", phase_counter)
    phase_counter += 1
    analyzer.logger.info("Tell IDA to analyze all of the code segments")
    cleanStart(analyzer, scs)
    idaapi.autoWait()

    ##############################################
    # 2. Observe and Locate the program features #
    ##############################################

    analyzer.logger.info("Phase #%d", phase_counter)
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
    idaapi.autoWait()

    ##########################
    # 3. Re-Analyze the code #
    ##########################

    analyzer.logger.info("Phase #%d", phase_counter)
    phase_counter += 1
    analyzer.logger.info("Tell IDA to re-analyze all of the code segments, using the added features")
    cleanStart(analyzer, scs, undef=True)
    idaapi.autoWait()

    ####################################
    # 4. Start handling the code types #
    ####################################

    if has_code_types:
        analyzer.logger.info("Phase #%d", phase_counter)
        phase_counter += 1
        analyzer.logger.info("Observe all code patterns from the improved analysis")
        if not gatherIntel(analyzer, scs, sds):
            analyzer.logger.error("Failed during intelligence gathering, exiting")
            return False
        analyzer.logger.info("Help IDA figure out the transition point between the different code types")
        # easy phase
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=False)
        idaapi.autoWait()
        # aggressive phase
        for sc in scs:
            thumbsUp(analyzer, sc, aggressive=True)

    ##########################
    # 5. Re-Analyze the code #
    ##########################

    if has_code_types:
        analyzer.logger.info("Phase #%d", phase_counter)
        phase_counter += 1
        analyzer.logger.info("Tell IDA to re-analyze all of the code segments, using the added features")
        finished = False
        while not finished:
            cleanStart(analyzer, scs, undef=True)
            # Remove false fptrs
            finished = analyzer.fptr_identifier.checkPointedFunctions() == 0

    ###########################
    # 6. Define the functions #
    ###########################

    analyzer.logger.info("Phase #%d", phase_counter)
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

    if has_code_types:
        analyzer.logger.info("Phase #%d", phase_counter)
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

    if analyzer.isCodeContainsData():
        analyzer.logger.info("Phase #%d", phase_counter)
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

    analyzer.logger.info("Phase #%d", phase_counter)
    phase_counter += 1
    analyzer.logger.info("Aggressively scan for functions")
    functionScan(analyzer, scs)
    # Declare functions from every code that left after the "conservative" scan
    aggressiveFunctionScan(analyzer, scs)

    ###############################
    # 10. Resolve function chunks #
    ###############################

    analyzer.logger.info("Phase #%d", phase_counter)
    phase_counter += 1
    analyzer.logger.info("Resolve all function chunks")
    resolveFunctionChunks(analyzer, scs)

    # If reached thus far, all was OK
    return True

def main():
    """Start Thumbs Up IDA plugin - Firmware version."""
    # Init the logger
    logger = Logger("Thumb's Up Logger", [("thumbs_up.log", "w", logging.DEBUG)], use_stdout=False, min_log_level=logging.INFO)
    logger.linkHandler(IdaLogHandler())
    # Locate the segments
    code_segments = filter(lambda x: x.type == 2, sark.segments())
    data_segments = filter(lambda x: x.type == 0, sark.segments())
    # Sanity checks
    if len(code_segments) == 0:
        logger.error("Failed to find any code segment, can't continue...")
        return
    if len(data_segments) == 0:
        logger.error("Failed to find any data segment, can't continue...")
        return
    # Notify the user about our segment decisions
    for sc in code_segments:
        logger.info("Code Segment: 0x%x - 0x%x", sc.startEA, sc.endEA)
    for sd in data_segments:
        logger.info("Data Segment: 0x%x - 0x%x", sd.startEA, sd.endEA)

    # Build up the analyzer
    analyzer = createAnalyzer(logger)
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

    # Start the analysis
    logger.info("Starting the analysis")
    result = analysisStart(analyzer, code_segments, data_segments)
    if result:
        logger.info("Successfully finished the analysis")
    else:
        logger.error("Encountered an error during the analysis")


# Invoke the main function
main()
