import collections
import traceback

######################################################################################################################
## Note: This factory is an indirection point, so we could (maybe) add support for more disassemblers in the future ##
######################################################################################################################

######################
## Global Variables ##
######################

disassembler_factory        = collections.OrderedDict()         # Mapping from disassembler name => DisasVerifier of the respective API object
disassembler_cmd_factory    = []                                # list of couples of the form (identifier_handler, class initializer)

def registerDisassembler(disas_verifier):
    """Register the disassembler in the overall factory.

    Args:
        disas_verifier (DisasVerifier): verifier for the wanted disassembler layer
    """
    global disassembler_factory

    disassembler_factory[disas_verifier.name()] = disas_verifier

def registerDisassemblerCMD(identifier_fn, init_fn):
    """Register the disassembler's command-line identifier in the overall factory.

    Args:
        identifier_fn (function): static identifier function
        init_fn (function): init function for the class instance
    """
    global disassembler_cmd_factory

    disassembler_cmd_factory.append((identifier_fn, init_fn))

def createDisassemblerHandler(logger):
    """Create the disassembler handler according to the host program.

    Args:
        logger (logger): logger instance (Must NOT be None)

    Return Value:
        disassembler handler that implements the declared API
    """
    for disas_name in disassembler_factory:
        verifier = disassembler_factory[disas_name]
        try:
            if not verifier.identify():
                continue
        except Exception as err:
            logger.error("Failed to identify disassembler \"%s\": %s", disas_name, err)
            logger.error(traceback.format_exc())
            continue
        logger.info("Chose the %s handler", disas_name)
        try:
            return verifier.disas()
        except Exception as err:
            logger.error("Failed to create disassembler handler \"%s\": %s", disas_name, err)
            logger.error(traceback.format_exc())
            return None
    logger.error("Failed to find a matching disassembler handler!")
    return None

def identifyDisassemblerHandler(program_path, logger):
    """Create the disassembler handler according to the given program path.

    Args:
        program_path (str): command line path to the disassembler program
        logger (logger): logger instance

    Return Value:
        disassembler handler that implements the declared API
    """
    for identifier, init in disassembler_cmd_factory:
        if identifier(program_path):
            disas = init(program_path)
            logger.debug("Chose the %s handler", disas.name())
            return disas

    logger.error("Failed to create a disassembler handler!")
    return None
