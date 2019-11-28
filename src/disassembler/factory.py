import collections

######################################################################################################################
## Note: This factory is an indirection point, so we could (maybe) add support for more disassemblers in the future ##
######################################################################################################################

######################
## Global Variables ##
######################

disassembler_factory        = collections.OrderedDict()         # Mapping from disassembler name => init function for the respective API object
disassembler_cmd_factory    = []                                # list of couples of the form (identifier_handler, class initializer)

def registerDisassembler(name, init_fn):
    """Register the disassembler in the overall factory.

    Args:
        name (str): name of the supported disassembler program (used as a unique identifier for it)
        init_fn (function): init function for the class instance
    """
    global disassembler_factory

    disassembler_factory[name] = init_fn

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
        logger (logger): logger instance (can be None sometimes)

    Return Value:
        disassembler handler that implements the declared API
    """
    for disas_name in disassembler_factory:
        try:
            handler = disassembler_factory[disas_name]
            if logger is not None and len(logger.handlers) > 0:
                logger.debug("Chose the %s handler", disas_name)
            return handler()
        except Exception:
            continue
    if logger is not None and len(logger.handlers) > 0:
        logger.error("Failed to create a disassembler handler!")
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
