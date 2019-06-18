import idaapi

analyzers_factory = {}      # Mapping from CPU name (according to IDA) to the init function

def createAnalyzer(logger):
    """Create a CPU-based analyzer to be used by the program.

    Args:
        logger (logger): logger instance

    Return Value:
        Created analyzer instance (None if CPU isn't supported yet)
    """
    # Code taken from:
    # https://reverseengineering.stackexchange.com/questions/11396/how-to-get-the-cpu-architecture-via-idapython
    # Kudos to tmr232
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    # quite rare
    else:
        bits = 16

    # At the moment we don't care about the processors endianness.

    # Check if we support this CPU
    proc_name = info.procName
    logger.info("Processor: %s, %dbit", proc_name, bits)
    if proc_name not in analyzers_factory:
        logger.error("Processor %s is NOT supported yet :(", proc_name)
        return None
    # Can now create the analyzer instance
    return analyzers_factory[proc_name](logger, bits)

def registerAnalyzer(cpu, init_fn):
    """Register the analyzer in the overall factory.

    Args:
        cpu (str): name of the CPU (using IDA's conventions)
        init_fn (function): init function for the class instance
    """
    global analyzers_factory

    analyzers_factory[cpu] = init_fn
