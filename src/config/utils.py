from score_config import *
import json
import collections
import os

#################################
## Basic Global Configurations ##
#################################

DISASSEMBLER_PATH = '/opt/ida-7.2/ida'
SCRIPT_PATH = os.path.abspath('analyze_src_file.py')

LIBRARY_NAME            = "Karta"
STATE_FILE_SUFFIX       = "_file_state.json"
LOG_FILE_SUFFIX         = "_analyze.log"
KNOWLEDGE_FILE_SUFFIX   = "_knowledge.json"

####################
## JSON Structure ##
####################

JSON_TAG_ANCHORS            = 'Anchors (Src Index)'
JSON_TAG_FILES              = 'Files'
JSON_TAG_MANUAL_ANCHORS     = 'Manual Anchors'
JSON_TAG_MANUAL_VERSIONS    = 'Manual Versions'
JSON_TAG_LIBRARY            = 'Library Name'

####################
## GUI Parameters ##
####################

REASON_MANUAL_ANCHOR    = "Manual Anchor - matched by the user"
REASON_ANCHOR           = "Anchor - Complex unique string / const"
REASON_FILE_HINT        = "Hint - Includes filename string"
REASON_AGENT            = "Agent - File-unique string / const"
REASON_NEIGHBOUR        = "Neighbour matching"
REASON_SINGLE_CALL      = "Single called (xref) option"
REASON_SINGLE_XREF      = "Single caller (xref) option"
REASON_FILE_SINGLETON   = "Last (referenced) function in file"
REASON_CALL_ORDER       = "Call order in caller function"
REASON_SWALLOW          = "Swallow - Identified IDA analysis problem"
REASON_COLLISION        = "Merge - Linker optimization merged source functions"
REASON_SCORE            = "Score-based Matching"
REASON_TRAPPED_COUPLE   = "Locked and ordered neighbouring functions"

REASON_DISABLED         = "ifdeffed out / inlined"
REASON_LIBRARY_UNUSED   = "Unused - No xrefs inside the open source"
REASON_STATIC_UNUSED    = "Unused - Static function without internal xrefs"

GUI_MATCH_REASONS       = [REASON_MANUAL_ANCHOR, REASON_ANCHOR, REASON_FILE_HINT, REASON_AGENT, REASON_NEIGHBOUR, REASON_SINGLE_CALL,
                           REASON_SINGLE_XREF, REASON_FILE_SINGLETON, REASON_CALL_ORDER, REASON_SWALLOW, REASON_COLLISION,
                           REASON_SCORE, REASON_TRAPPED_COUPLE]

GUI_CMD_IMPORT_SELECTED = "Import Selected"
GUI_CMD_IMPORT_MATCHED  = "Import ALL Matches"

GUI_COLOR_DARK_GREEN    = 0x0f6000
GUI_COLOR_GREEN         = 0x3c8e38
GUI_COLOR_GRAY          = 0x9e9e9e
GUI_COLOR_DARK_RED      = 0x0d00ba
GUI_COLOR_RED           = 0x3643f4

######################
## Global Variables ##
######################

windows_config              = False                         # Configuration flag - are we handling a binary that was compiled to windows?
matching_mode               = False                         # Configuration flag - are we running the matching script now?

global_logger               = None                          # Global logger instance (from elementals)
disas_layer                 = None                          # Disassembler API layer (according to the program we use for our disassembling)
matched_library_name        = None                          # Name of the matched open source library

src_func_class              = None                          # Source function context layer
bin_func_class              = None                          # Binary function context layer
island_func_class           = None                          # Island function context layer

src_seen_consts             = []
src_seen_strings            = []
src_functions_list          = []
src_functions_ctx           = []
src_file_mappings           = collections.OrderedDict()

src_instr_count             = 0
bin_instr_count             = 0
num_instr_samples           = 0
num_neighbours_matched      = 0
num_neighbours_mismatched   = 0

######################
## Inner Exceptions ##
######################

class KartaException(Exception):
    """An exception that signals Karta can't continue the matching."""

    pass

##########
## Init ##
##########

def initUtils(logger, disas, invoked_before=False):
    """Prepare the utils global variables for a new script execution.

    Args:
        logger (logger): logger instance
        disas (disassembler): disassembler handler instance
        invoked_before (bool): True iff was invoked before, and is part of a repetitive invocation (False by default)
    """
    global global_logger, disas_layer, src_seen_consts, src_seen_strings, src_functions_list, src_functions_ctx, src_file_mappings
    # same as the init list on the top of the file
    src_seen_consts     = []
    src_seen_strings    = []
    src_functions_list  = []
    src_functions_ctx   = []
    src_file_mappings   = collections.OrderedDict()
    # don't forget the instruction ratio
    resetRatio()
    # don't forget the neighbour scoring
    resetScoring()
    # don't do this initialization after the first invocation
    if not invoked_before:
        # init the logger
        global_logger = logger
        # get our disassembler handler
        disas_layer = disas
        # register the log handler
        global_logger.linkHandler(disas_layer.logHandler())

##################
## Config Files ##
##################

def constructConfigPath(library_name, library_version):
    """Generate the name for the JSON config file that will store the library's canonical data.

    Args:
        library_name (str): name of the library (as extracted by the identifiers)
        library_version (str): version of the library (as extracted by the identifiers)

    Return value:
        file name for the JSON config file
    """
    global matched_library_name

    # niec hook to save this for future use
    matched_library_name = library_name

    return library_name + "_" + library_version + ("_windows" if isWindows() else "") + ".json"

def functionsToFile(file_name, contexts):
    """Store all of the file's functions into a state file.

    Args:
        file_name (str): file name of a compiled source file
        contexts (list): list of FunctionContext instances for all of the functions in the file
    """
    # Temporary JSON (later will be merged to a single JSON)
    fd = open(file_name + STATE_FILE_SUFFIX, "w")
    json.dump(map(lambda c: c.serialize(), contexts), fd)
    fd.close()

def parseFileStats(file_name, functions_config):
    """Parse the file metadata from the given file.

    Args:
        file_name (str): name of the compiled file
        functions_config (list): list of serialized functions, as extracted from the JSON file
    """
    global src_seen_consts, src_seen_strings, src_functions_list, src_functions_ctx, src_file_mappings

    src_file_mappings[file_name] = []
    source_index = len(src_functions_list)
    for func_config in functions_config:
        context = sourceContext().deserialize(func_config, source_index)
        context.file = file_name
        # accumulate the artifacts
        src_seen_consts  += context.consts
        src_seen_strings += context.strings
        # register the seen function
        src_functions_list.append(context.name)
        src_functions_ctx.append(context)
        src_file_mappings[file_name].append(context)
        source_index += 1

def getContextsStats():
    """Return the statistics of the analyzed source functions.

    Return Value:
        src_seen_strings, src_seen_consts, src_functions_list
    """
    return src_seen_strings, src_seen_consts, src_functions_list

def constructLogPath(bin_path=None):
    """Generate the name for the log file of the currently analyzed binary file.

    Args:
        bin_path (str, Optional): path to the compiled binary file (None by default)

    Return value:
        file name for the log file
    """
    return (bin_path if bin_path is not None else disas_layer.inputFile()) + LOG_FILE_SUFFIX

def accumulatedKnowledgePath(bin_path=None):
    """Generate the name for the configuration file of the currently analyzed binary file.

    Args:
        bin_path (str, Optional): path to the compiled binary file (None by default)

    Return value:
        file name for the config file with the accumulated information
    """
    return (bin_path if bin_path is not None else disas_layer.databaseFile()) + KNOWLEDGE_FILE_SUFFIX

def loadKnowledge(bin_path=None):
    """Load the .json configuration for the current binary file, if exists.

    Args:
        bin_path (str, Optional): path to the compiled binary file (None by default)

    Return value:
        json parsed information, or None if none exist
    """
    json_path = accumulatedKnowledgePath(bin_path)
    if not os.path.exists(json_path):
        return None

    fd = open(json_path, 'r')
    config_dict = json.load(fd, object_pairs_hook=collections.OrderedDict)
    fd.close()
    return config_dict

def storeKnowledge(json_config, bin_path=None):
    """Store the .json configuration for the current binary file.

    Args:
        json_config (dict): json configuration content
        bin_path (str, Optional): path to the compiled binary file (None by default)
    """
    json_path = accumulatedKnowledgePath(bin_path)
    fd = open(json_path, 'w')
    json.dump(json_config, fd)
    fd.close()

#########################
## Adaptive heuristics ##
#########################

def recordInstrRatio(src_instr, bin_instr):
    """Record a single ratio sample for measuring src_instr / bin_instr ratio.

    Args:
        src_instr (int): number of instructions in given source sample
        bin_instr (int): number of instructions in given binary sample
    """
    global src_instr_count, bin_instr_count, num_instr_samples

    src_instr_count   += src_instr
    bin_instr_count   += bin_instr
    num_instr_samples += 1

def recordNeighbourMatch(is_neighbour):
    """Record a single neighbour matching statistics for scaling the score boost.

    Args:
        is_neighbour (bool): True iff matched neighbours
    """
    global num_neighbours_matched, num_neighbours_mismatched

    num_neighbours_matched    += 1 if is_neighbour else 0
    num_neighbours_mismatched += 0 if is_neighbour else 1

def resetRatio():
    """Prepare the ratio variables for a new script execution."""
    global src_instr_count, bin_instr_count, num_instr_samples
    # same as the init list on the top of the file
    src_instr_count         = 0
    bin_instr_count         = 0
    num_instr_samples       = 0

def resetScoring():
    """Prepare the scoring variables for a new script execution."""
    global num_neighbours_matched, num_neighbours_mismatched
    # same as the init list on the top of the file
    num_neighbours_matched    = 0
    num_neighbours_mismatched = 0

def getNeighbourScore():
    """Return the current (scaled) score boost for neighbours.

    Return Value:
        Scaled neighbour score boost
    """
    num_matched = num_neighbours_matched + num_neighbours_mismatched
    # we don't any input
    if num_matched == 0:
        # start safe
        return 0
    # start safely
    safe_score = 1 if num_matched >= 10 else 0.5
    # calculate the ratio
    ratio = (num_neighbours_matched * 1.0 / num_matched) * safe_score
    if ratio > LOCATION_BOOST_LOW_THRESHOLD:
        ratio = 1
    return LOCATION_BOOST_SCORE * ratio

def areNeighboursSafe():
    """Check if the neighbour score is stable enough to be used for generating candidates.

    Return Value:
        True iff picking neighbour candidates is safe
    """
    return LOCATION_BOOST_SCORE * LOCATION_BOOST_LOW_THRESHOLD <= getNeighbourScore()

###################
## Const Scoring ##
###################

def countSetBits(const):
    """Count the set ('1') bits in the given numeric constant.

    Args:
        const (int): numeric constant to rank

    Return Value:
        Number of set ('1') bits
    """
    # we only work on unsigned values
    if const < 0:
        const += 2 ** NUM_BITS_IN_CONST
    # simply count them
    return bin(const).count('1')

def measureBitsVariance(const):
    """Measures the bits "entropy", i.e. the variance of the bit flips.

    Args:
        const (int): numeric constant to rank

    Return Value:
        Variance level of the bit flips
    """
    variance = 0
    level = 1
    const = bin(const)[2:]
    while const.count('0') != len(const) and level < 4:
        cur_const = '1' if const[0] != const[-1] else '0'
        last_bit = const[0]
        for bit in const[1:]:
            cur_const += '1' if bit != last_bit else '0'
            last_bit = bit
        const = cur_const
        variance += level * abs(NUM_BITS_IN_CONST * 0.5 - abs(cur_const.count('1') - NUM_BITS_IN_CONST * 0.5))
        level += 1
    return variance

def measureBitsEntropy(const):
    """Use heuristics to measure the "entropy" of the given numeric value.

    Args:
        const (int): numeric constant to be measured

    Return Value:
        Overall "entropy" score of the given numeric constant
    """
    # we only work on unsigned values
    if const < 0:
        const += 2 ** NUM_BITS_IN_CONST
    # variance score (embeds inside it the number of bits)
    return measureBitsVariance(const) * 1.0 / (NUM_BITS_IN_CONST / 2)

def rankConst(const, context):
    """Score a given constant, in the context of its function.

    Args:
        const (int): numeric constant to rank
        context (FunctionContext): function context or None (for islands)

    Return Value:
        Overall score of the given numeric constant
    """
    # 0. Ignore stack variable offsets
    if context is not None and const < context.frame + FRAME_SAFETY_GAP:
        return 0
    # 1. Measure the entropy
    score = measureBitsEntropy(const)
    # 2. Scale it: use a wider range, and spread the values
    score = score * score
    # 3. Boost special values
    if const in CONST_SPECIAL_VALUES:
        score += CONST_BOOST_SPECIAL
    # 4. Boost bit flags that are bigger than the frame size
    if context is not None and countSetBits(const) == 1 and const > context.frame:
        score += CONST_BOOST_BIT_FLAG
    return score

##################
## Global State ##
##################

def getDisas():
    """Return the global disassembler layer instance.

    Return Value:
        Disassembler layer instance
    """
    return disas_layer

def getSourceFunctions():
    """Return the data-structures of the analyzed source functions.

    Return Value:
        src_functions_list, src_functions_ctx, src_file_mappings
    """
    return src_functions_list, src_functions_ctx, src_file_mappings

def setWindowsMode():
    """Update the global flag to handle windows compiled binaries."""
    global windows_config

    windows_config = True

def isWindows():
    """Return the binary category: Windows or Other.

    Return Value:
        True iff analyzing a windows compiled binary
    """
    return windows_config

def setMatchingMode():
    """Update the global flag to signal that we are now in a matching phase."""
    global matching_mode

    matching_mode = True

def isMatching():
    """Return the script phase: Matching or Compilation.

    Return Value:
        True iff matching against a given binary
    """
    return matching_mode

def setDisassemblerPath(prompter):
    """Update the disassembler path according to input from the user.

    Args:
        prompter (prompter): prompter elementals instance
    """
    global DISASSEMBLER_PATH

    new_path = prompter.input("Please insert the command (path) needed in order to execute your disassembler (IDA for instance) (%s): " % (DISASSEMBLER_PATH))
    if len(new_path.strip()) != 0:
        DISASSEMBLER_PATH = new_path

def getDisasPath():
    """Return the updated path to the disassembler.

    Return Value:
        The (updated) path to the disassembler program
    """
    return DISASSEMBLER_PATH

def libraryName():
    """Return the name of the currently matched open source library.

    Return Value:
        String name of the matched library
    """
    return matched_library_name

##############################
## Active Function Contexts ##
##############################

def registerContexts(src_func, bin_func, island_func):
    """Register the classes used to create Source and Binary function contexts.

    Args:
        src_func (class): Ctor() for the source function context
        bin_func (class): Ctor() for the binary function context
        island_func (class): Ctor() for the island function context
    """
    global src_func_class, bin_func_class, island_func_class

    src_func_class      = src_func
    bin_func_class      = bin_func
    island_func_class   = island_func

def sourceContext():
    """Return the registered context for the source functions.

    Return Value:
        Ctor() for the source function context
    """
    return src_func_class

def binaryContext():
    """Return the registered context for the binary functions.

    Return Value:
        Ctor() for the binary function context
    """
    return bin_func_class

def islandContext():
    """Return the registered context for the island functions.

    Return Value:
        Ctor() for the island function context
    """
    return island_func_class
