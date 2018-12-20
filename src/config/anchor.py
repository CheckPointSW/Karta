from anchor_config import *
from config.utils  import *

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
    case = 1
    max_case = 5
    while case <= max_case:
        # 1. Huge unique string
        if case == 1:
            huge_strings = filter(lambda x: seen_strings.count(x) == 1, filter(lambda x: len(x) >= STRING_HUGE_LIMIT, context.strings))
            if len(huge_strings) >= STRING_HUGE_GROUP:
                logger.debug("Found an Anchor: %s ==> Unique HUGE string (%d)", context.name, len(huge_strings[0]))
                return True, STRING_HUGE_GROUP, huge_strings
        # 2. Unique string with a function name in it
        elif case == 2:
            for unique_str in filter(lambda x: seen_strings.count(x) == 1, context.strings):
                for func_name in functions_list:
                    if func_name in unique_str:
                        logger.debug("Found an Anchor: %s ==> Unique string (%s) containing a function name (%s)", context.name, unique_str, func_name)
                        return True, 1, [unique_str]
        # 3. X unique strings with long length
        elif case == 3:
            unique_long_strings = filter(lambda x: seen_strings.count(x) == 1, filter(lambda x: len(x) >= STRING_LONG_LIMIT, context.strings))
            if len(unique_long_strings) >= STRING_LONG_GROUP:
                logger.debug("Found an Anchor: %s ==> %d unique long strings", context.name, len(unique_long_strings))
                return True, STRING_LONG_GROUP, unique_long_strings
        # 4. X unique strings with medium length
        elif case == 4:
            unique_medium_strings = filter(lambda x: seen_strings.count(x) == 1, filter(lambda x: len(x) >= STRING_MEDIUM_LIMIT, context.strings))
            if len(unique_medium_strings) >= STRING_MEDIUM_GROUP:
                logger.debug("Found an Anchor: %s ==> %d unique medium strings", context.name, len(unique_medium_strings))
                return True, STRING_MEDIUM_GROUP, unique_medium_strings
        # 5. Unique const with high entropy
        elif case == 5:
            unique_complex_consts = filter(lambda x: seen_consts.count(x) == 1, filter(lambda x: rankConst(x, context) >= CONST_COMPLEX_LIMIT, context.consts))
            if len(unique_complex_consts) >= CONST_COMPLEX_GROUP:
                logger.debug("Found an Anchor: %s ==> %d unique complex consts: %s", context.name, len(unique_complex_consts), hex(unique_complex_consts[0]))
                return False, CONST_COMPLEX_GROUP, unique_complex_consts
        case += 1
    # we found nothing if we reached this line
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
    case = 1
    max_case = 3
    while case <= max_case:
        # 1. Medium unique string
        if case == 1:
            medium_strings = filter(lambda x: x in unique_strings, filter(lambda x: len(x) >= STRING_MEDIUM_LIMIT, context.strings))
            if len(medium_strings) > 0:
                logger.debug("Found an Agent: %s ==> Unique medium string (%d)", context.name, len(medium_strings[0]))
                return True, 1, medium_strings
        # 2. X unique strings with short length
        elif case == 2:
            unique_short_strings = filter(lambda x: x in unique_strings, filter(lambda x: len(x) >= STRING_SHORT_LIMIT, context.strings))
            if len(unique_short_strings) >= STRING_SHORT_GROUP:
                logger.debug("Found an Agent: %s ==> %d unique long strings", context.name, len(unique_short_strings))
                return True, STRING_SHORT_GROUP, unique_short_strings
        # 3. Unique const with medium entropy
        elif case == 3:
            unique_medium_consts = filter(lambda x: x in unique_consts, filter(lambda x: rankConst(x, context) >= CONST_MEDIUM_LIMIT, context.consts))
            if len(unique_medium_consts) > 0:
                logger.debug("Found an Agent: %s ==> %d unique medium consts", context.name, len(unique_medium_consts))
                return False, 1, unique_medium_consts
        case += 1
    # we found nothing if we reached this line
    return False, 0, None
