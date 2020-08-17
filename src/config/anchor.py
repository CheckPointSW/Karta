from .anchor_config import *
from config.utils   import *

def isAnchor(context, seen_strings, seen_consts, functions_list, logger):
    """Check if the given context represents an Anchor function.

    Args:
        context (FunctionContext): canonical representation of a source function
        seen_strings (set): set of unique strings to be used for the scoring
        seen_consts (set): set of unique (numeric) consts to be used for the scoring
        functions_list (list): list of all source functions names
        logger (logger): logger instance

    Return Value:
        is string criteria (True / False), threshold count, Matching anchor criteria (list of string for instance), or None if not an anchor
    """
    unique_strings = [s for s in context.strings if seen_strings.count(s) == 1]
    # Case #1. Huge unique string
    huge_strings = [s for s in unique_strings if len(s) >= STRING_HUGE_LIMIT]
    if len(huge_strings) >= STRING_HUGE_GROUP:
        logger.debug(f"Found an Anchor: {context.name} ==> Unique HUGE string ({len(huge_strings[0])})")
        return True, STRING_HUGE_GROUP, huge_strings

    # Case #2. Unique string with a function name in it
    for unique_str in unique_strings:
        for func_name in functions_list:
            if func_name in unique_str:
                logger.debug(f"Found an Anchor: {context.name} ==> Unique string ({unique_str}) containing a function name ({func_name})")
                return True, 1, [unique_str]

    # Case #3. X unique strings with long length
    unique_long_strings = [s for s in unique_strings if len(s) >= STRING_LONG_LIMIT]
    if len(unique_long_strings) >= STRING_LONG_GROUP:
        logger.debug(f"Found an Anchor: {context.name} ==> {len(unique_long_strings)} unique long strings")
        return True, STRING_LONG_GROUP, unique_long_strings

    # Case #4. X unique strings with medium length
    unique_medium_strings = [s for s in unique_strings if len(s) >= STRING_MEDIUM_LIMIT]
    if len(unique_medium_strings) >= STRING_MEDIUM_GROUP:
        logger.debug(f"Found an Anchor: {context.name} ==> {len(unique_medium_strings)} unique medium strings")
        return True, STRING_MEDIUM_GROUP, unique_medium_strings

    # Case #5. Unique const with high entropy
    unique_complex_consts = [c for c in context.consts if rankConst(c, context) >= CONST_COMPLEX_LIMIT and seen_consts.count(c) == 1]
    if len(unique_complex_consts) >= CONST_COMPLEX_GROUP:
        logger.debug(f"Found an Anchor: {context.name} ==> len(unique_complex_consts) unique complex consts: 0x{unique_complex_consts[0]:x}")
        return False, CONST_COMPLEX_GROUP, unique_complex_consts

    # If we reached this line it means we found nothing :(
    return False, 0, None

def isAgent(context, unique_strings, unique_consts, logger):
    """Check if the given context represents an Agent function inside it's file.

    Args:
        context (FunctionContext): canonical representation of a source function
        unique_strings (set): set of unique strings to be used for the scoring
        unique_consts (set): set of unique (numeric) consts to be used for the scoring
        logger (logger): logger instance

    Return Value:
        is string criteria (True / False), threshold count, Matching agent criteria (list of string for instance), or None if not an agent
    """
    unique_local_strings = unique_strings & context.strings
    # Case #1. Medium unique string
    medium_strings = [s for s in unique_local_strings if len(s) >= STRING_MEDIUM_LIMIT]
    if len(medium_strings) > 0:
        logger.debug(f"Found an Agent: {context.name} ==> Unique medium string ({len(medium_strings[0])})")
        return True, 1, medium_strings

    # Case #2. X unique strings with short length
    unique_short_strings = [s for s in unique_local_strings if len(s) >= STRING_SHORT_LIMIT]
    if len(unique_short_strings) >= STRING_SHORT_GROUP:
        logger.debug(f"Found an Agent: {context.name} ==> {len(unique_short_strings)} unique long strings")
        return True, STRING_SHORT_GROUP, unique_short_strings

    # Case #3. Unique const with medium entropy
    unique_medium_consts = [c for c in unique_consts & context.consts if rankConst(c, context) >= CONST_MEDIUM_LIMIT]
    if len(unique_medium_consts) > 0:
        logger.debug(f"Found an Agent: {context.name} ==> {len(unique_medium_consts)} unique medium consts")
        return False, 1, unique_medium_consts

    # If we reached this line it means we found nothing :(
    return False, 0, None
