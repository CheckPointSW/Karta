import sark
import idc
import idaapi
from collections            import defaultdict
from utils.code_metric      import CodeMetric
from utils.code_regions     import CodeRegion, CodeRegions

def gatherIntel(analyzer, scs, sds):
    """Gather all of the intelligence about the program's different features.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments to work on
        sds (list): list of (sark) data segments to work on

    Return Value:
        True iff everything was successful
    """
    # calibrate the features needed for the function classifier
    if not analyzer.func_classifier.calibrateFunctionClassifier(scs):
        return False
    # Observe function features from identified functions
    analyzer.func_classifier.trainFunctionClassifier(scs)
    # calibrate the features needed for the function type classifier
    if analyzer.hasCodeTypes():
        if not analyzer.func_classifier.calibrateFunctionTypeClassifier(scs):
            return False
        # Observe function features from identified functions
        analyzer.func_classifier.trainFunctionTypeClassifier(scs)
    # Observe the code features from all of the code
    if analyzer.isCodeContainsData() and analyzer.locals_identifier.observeLocalConstants(scs) is None:
        return False
    # Everything went well if we reached this line
    return True

def cleanStart(analyzer, scs, undef=False):
    """Clean the selected code segments, and re-analyzer them using the gathered metadata until now.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments to work on
        undef (bool, optional): True iff should undefine the code segments (False by default)
    """
    for sc in scs:
        if undef:
            analyzer.logger.info("Undefining code segment: 0x%x - 0x%x", sc.startEA, sc.endEA)
            sark.data.undefine(sc.startEA, sc.endEA)
            analyzer.logger.info("Marking all known switch tables in the segment")
            analyzer.switch_identifier.markSwitchTables(sc)
    analyzer.logger.info("Marking all known fptr functions")
    analyzer.fptr_identifier.makePointedFunctions()
    for sc in scs:
        analyzer.logger.info("Re-Analyzing code segment: 0x%x - 0x%x", sc.startEA, sc.endEA)
        idaapi.analyze_area(sc.startEA, sc.endEA)
        idaapi.autoWait()

def convertRegion(analyzer, start_ea, end_ea):
    """Convert (Cancel) a given code region (change it's code type).

    Args:
        analyzer (instance): analyzer instance to be used
        start_ea (int): effective start address of the region
        end_ea (int): effective end address of the region
    """
    wanted_code_type = analyzer.codeType(end_ea)
    analyzer.logger.info("Converting code region of type %d to %d: 0x%x - 0x%x (%d)", analyzer.codeType(start_ea), wanted_code_type, start_ea, end_ea, end_ea - start_ea)
    # Make sure it will be treated as code
    idc.MakeUnknown(start_ea, end_ea - start_ea, 0)
    # manually set the wanted value over the entire region
    analyzer.setCodeType(start_ea, end_ea, wanted_code_type)
    # now reanalyze the new section
    idaapi.analyze_area(analyzer.alignTransitionAddress(start_ea, wanted_code_type), end_ea)

def resizeRegion(analyzer, start_ea, end_ea, new_start_ea, new_end_ea):
    """Resize a given code region, according to the new dimensions.

    Args:
        analyzer (instance): analyzer instance to be used
        start_ea (int): effective start address of the original region
        end_ea (int): effective end address of the original region
        new_start_ea (int): effective start address for the new region
        new_end_ea (int): effective end address for the new region
    """
    analyzer.logger.info("Resizing code region of type %d: 0x%x (0x%x) - 0x%x (0x%x)", analyzer.codeType(start_ea), new_start_ea, start_ea, end_ea, new_end_ea)
    code_type_before = analyzer.codeType(min(start_ea, new_start_ea) - 1)
    code_type_middle = analyzer.codeType(start_ea)
    code_type_after  = analyzer.codeType(max(end_ea, new_end_ea))
    # Make sure it will be treated as code
    fix_regions = []
    if new_start_ea < start_ea:
        fix_regions.append((new_start_ea, start_ea))
    elif new_start_ea != start_ea:
        fix_regions.append((start_ea, new_start_ea))
    if end_ea < new_end_ea:
        fix_regions.append((end_ea, new_end_ea))
    elif end_ea != new_end_ea:
        fix_regions.append((new_end_ea, end_ea))
    # Make the changed parts unknown, before re-analyzing them
    for region_start, region_end in fix_regions:
        idc.MakeUnknown(region_start, region_end - region_start, 0)
    # manually set the wanted value over the entire region
    if start_ea < new_start_ea:
        analyzer.setCodeType(start_ea, new_start_ea, code_type_before)
    elif start_ea != new_start_ea:
        analyzer.setCodeType(new_start_ea, start_ea, code_type_middle)
    if end_ea < new_end_ea:
        analyzer.setCodeType(end_ea, new_end_ea, code_type_middle)
    elif end_ea != new_end_ea:
        analyzer.setCodeType(new_end_ea, end_ea, code_type_after)
    # now reanalyze the new section
    for region_start, region_end in fix_regions:
        idaapi.analyze_area(region_start, region_end)

def functionScan(analyzer, scs):
    """Scan the code segment and try to define functions.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments

    Notes
    -----
        An attempt to declare a function will occur if we found:
        1. Code line after a previous function - and it looks like the beginning of a function of the same code type
        2. Unknown after a previous function - and it looks like the beginning of a function of the estimated code type
    """
    for sc in scs:
        search_func = False
        just_started = True
        line = sark.Line(sc.startEA)
        while line.startEA < sc.endEA:
            # we don't care about data lines
            if line.is_data:
                line = line.next
                continue
            # check for code lines
            if line.is_code:
                try:
                    sark.Function(line.startEA)
                    search_func = False
                    just_started = True
                    line = line.next
                    continue
                except sark.exceptions.SarkNoFunction:
                    if just_started:
                        just_started = False
                    else:
                        search_func = True
            # If we are searching for a function, simply continue
            if search_func or analyzer.switch_identifier.isSwitchCase(line.startEA):
                line = line.next
                continue
            # If this is code, check that it matches the start of a function, and make it a function
            if line.is_code and analyzer.func_classifier.predictFunctionStartMixed(line.startEA):
                if not idc.MakeFunction(line.startEA):
                    line = line.next
                else:
                    analyzer.logger.debug("Declared a function at: 0x%x", line.startEA)
                continue
            # Code, and doesn't look like a function's start
            if line.is_code:
                # skip for now
                line = line.next
                continue
            # If unknown, check if a function and don't try to keep the same code type
            if line.is_unknown:
                guess_code_type = analyzer.func_classifier.predictFunctionStartType(line.startEA)
                original_code_type = analyzer.codeType(line.startEA)
                if analyzer.func_classifier.predictFunctionStart(line.startEA, guess_code_type):
                    if original_code_type != guess_code_type:
                        analyzer.setCodeType(line.startEA, line.startEA + 1, guess_code_type)
                    if not idc.MakeFunction(line.startEA):
                        analyzer.setCodeType(line.startEA, line.startEA + 1, original_code_type)
                        line = line.next
                    else:
                        analyzer.logger.debug("Declared a function at: 0x%x (Type %d, Local type %d)", line.startEA, guess_code_type, original_code_type)
                    continue
                # otherwise, do nothing
                line = line.next
                continue

def aggressiveFunctionScan(analyzer, scs):
    """Aggressively scan the code segment and try to define functions.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments
    """
    for sc in scs:
        search_func = False
        just_started = True
        line = sark.Line(sc.startEA)
        while line.startEA < sc.endEA:
            # we don't care about non-code lines
            if not line.is_code:
                line = line.next
                continue
            # check for code lines
            if line.is_code:
                try:
                    sark.Function(line.startEA)
                    search_func = False
                    just_started = True
                    line = line.next
                    continue
                except sark.exceptions.SarkNoFunction:
                    if just_started:
                        just_started = False
                    else:
                        search_func = True
            # If we are searching for a function, simply continue
            if search_func or analyzer.switch_identifier.isSwitchCase(line.startEA):
                line = line.next
                continue
            # This is code, make it a function
            if not idc.MakeFunction(line.startEA):
                line = line.next
            else:
                analyzer.logger.debug("Declared a function at: 0x%x", line.startEA)

def dataScan(analyzer, scs):
    """Scan the code segments for orphan data blobs that represent analysis errors.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments
    """
    # First Scan - unreffed data chunks inside functions ==> should be converted to code
    for sc in scs:
        first_line = None
        end_line   = None
        for line in sc.lines:
            # After the first, the rest of the lines should have 0 crefs
            if first_line is not None and ((not line.is_data) or len(list(line.drefs_to)) > 0 or len(list(line.crefs_to)) > 0):
                end_line = line
            # we only care about data lines with a single cref from the previous line
            elif first_line is None and ((not line.is_data) or len(list(line.drefs_to)) > 0 or len(list(line.crefs_to)) != 1 or sark.Line(list(line.crefs_to)[0]).next != line):
                end_line = line
            # don't mark switch entries
            elif analyzer.switch_identifier.isSwitchEntry(line.startEA):
                end_line = line
            # Finally, check if it could be a function of some type
            elif first_line is None:
                first_line = line
                continue
            # Found an adjacent suitable line
            else:
                continue
            # Now check if we found something (end_line is always != None at this point)
            if first_line is not None and end_line is not None:
                chunk_start = first_line.startEA
                chunk_end   = end_line.startEA
                # check that the chunk before us is not the end of a function
                if analyzer.func_classifier.predictFunctionEnd(chunk_start):
                    # shouldn't really happen, do nothing in this case
                    pass
                # data chunk in the middle of a function, and not at it's end - convert it to code
                else:
                    analyzer.logger.debug("In-Function data chunk at: 0x%x - 0x%x (%d)", chunk_start, chunk_end, chunk_end - chunk_start)
                    idc.MakeUnknown(chunk_start, chunk_end - chunk_start, 0)
                    idc.MakeCode(chunk_start)
                # reset the vars
                first_line = None
                end_line   = None

    # Second scan - unreffed data chunks outside of functions ==> new functions, possibly of different code type
    size_limit = analyzer.func_classifier.functionStartSize()
    analyzer.logger.debug("Size limit for data scan is: %d", size_limit)
    conversion_candidates = []
    # recon pass
    for sc in scs:
        first_line = None
        end_line   = None
        for line in sc.lines:
            # we only care about data lines without xrefs
            if (not line.is_data) or len(list(line.crefs_to)) > 0 or len(list(line.drefs_to)) > 0:
                end_line = line
            # check if it's big enough for the classifier
            elif line.size < size_limit:
                end_line = line
            # check if it looks like a string
            elif analyzer.str_identifier.isLocalAsciiString(line.startEA, check_refs=False):
                analyzer.str_identifier.defineAsciiString(line.startEA)
                end_line = line
            # make sure it isn't a switch entry
            elif analyzer.switch_identifier.isSwitchEntry(line.startEA):
                end_line = line
            # Finally, check if it could be a function of some type
            elif first_line is None:
                first_line = line
                continue
            # Found an adjacent suitable line
            else:
                continue
            # Now check if we found something (end_line is always != None at this point)
            if first_line is not None and end_line is not None:
                chunk_start = first_line.startEA
                chunk_end   = end_line.startEA
                guess_code_type = analyzer.func_classifier.predictFunctionStartType(chunk_start)
                original_code_type = analyzer.codeType(chunk_start)
                analyzer.logger.debug("Found a data chunk at: 0x%x - 0x%x (%d), (Type %d, Local type %d)", chunk_start, chunk_end, chunk_end - chunk_start, guess_code_type, original_code_type)
                # Check if this is the beginning of a function
                if analyzer.func_classifier.predictFunctionStart(chunk_start, guess_code_type):
                    conversion_candidates.append((chunk_start, chunk_end, guess_code_type, original_code_type))
                # reset the vars
                first_line = None
                end_line   = None
    # conversion pass
    for chunk_start, chunk_end, guess_code_type, original_code_type in conversion_candidates:
        analyzer.logger.info("Found an isolated data chunk at: 0x%x - 0x%x (%d), (Type %d, Local type %d)", chunk_start, chunk_end, chunk_end - chunk_start, guess_code_type, original_code_type)
        idc.MakeUnknown(chunk_start, chunk_end - chunk_start, 0)
        if original_code_type != guess_code_type:
            analyzer.setCodeType(chunk_start, chunk_end, guess_code_type)
        idaapi.analyze_area(chunk_start, chunk_end)
        idc.MakeFunction(chunk_start)

def thumbsUp(analyzer, sc, aggressive=False, align=False):
    """Use various metrics in order to locate / fix code type transitions.

    Args:
        analyser (instance): analyzer instance to be used
        sc (segment): (sark) code segment to work on
        aggressive (bool, optional): True iff should use aggressive heuristics (False by default)
        align (bool, optional): True iff should use align-based heuristics (False by default)

    Notes
    -----
        1. Convert (cancel) a code region that is contained inside the same function, and contains unexplored bytes (not a Chunk, and contains no functions)
        2. Convert (cancel) a code region that is misaligned and contains no functions
        3. Aggressive - Convert (cancel) a code region if the classifier doesn't agree on it's start
        4. Aggressive - Convert (cancel) a code region if it contains illegal code lines / unknowns, and it contains no functions
        5. Aggressive - Convert (cancel) a pointed code region that could be misinterpreted, and that contains no functions (+ delete the fptr)
        6. Aggressive - Convert (cancel) a code region that begins on a function start, that could be misinterpreted, and that contains no functions
        7. Resize a code region that needs a little alignment
        8. In all of the heuristics, if the code region before us was OK and we merged with him, there is no need to check it again.
    """
    regions_fixed = 1
    line = sark.Line(sc.startEA)
    regions = CodeRegions()
    first_round = True
    is_fptr_pointed = False
    code_aligned = False
    region_start = 0
    metric = None
    # Only continue if we changed something during the current round
    while regions_fixed > 0:
        regions_fixed = 0
        starting_new_region = True  # edge case for the first line in the section
        dummy_mode = False
        prev_code_type = None
        region_converted = False
        region_code_type = None
        if not first_round:
            interesting_regions = regions.changedRegions()
            analyzer.logger.debug("%d interesting regions", len(interesting_regions))
            # edge case, if we have nothing to do
            if len(interesting_regions) == 0:
                break
            line = sark.Line(interesting_regions[0].start)
            region_offset = -1
        # iterate the current region
        while line.startEA < sc.endEA:
            if not starting_new_region:
                # check if we found a transitions
                new_code_type = analyzer.codeType(line.startEA)
                # no change, just keep on
                if region_code_type == new_code_type:
                    if not dummy_mode:
                        metric.record(line)
                    line = line.next
                    continue
                # we found a transition
                region_end = line.startEA
                region_converted = False
                if first_round:
                    region = CodeRegion(region_start, region_end, region_code_type)
                    regions.insert(region)
                # in dummy mode, don't do a thing
                if dummy_mode:
                    metrics = []
                    analyzer.logger.debug("Dummy region of code type %d in range 0x%x - 0x%x", region_code_type, region_start, region_end)
                # actually do something
                else:
                    # get the metrics
                    metric.stop(region_end)
                    # suffix / align metrics
                    align_metric = metric.alignMetric()
                    metrics = [metric] + ([align_metric] if align_metric is not None else [])
                    first_metric_region_fixed = True
                    aligned_region_fixed      = True
                # Examine both metrics
                for code_metric in metrics:
                    contains_functions = code_metric.containsFunctions()
                    unknown_count, unknown_ratio = code_metric.unknowns()
                    illegal_count, illegal_ratio = code_metric.illegals()
                    has_unknown_or_illegal = unknown_count > 0 or illegal_count > 0
                    containing_function = code_metric.containingFunction()
                    start_function = code_metric.startFunction()
                    metric_region_start, metric_region_end = code_metric.borders()
                    metric_region_size = metric_region_end - metric_region_start
                    # special case for the last metric
                    if code_metric == align_metric:
                        aligned_region = True
                        metric_name = "Aligned"
                    else:
                        aligned_region = False
                        metric_name = "Regular"
                    # debug prints
                    analyzer.logger.debug("%s Metric: Code type %d used in range 0x%x - 0x%x (Pointed: %s, Contains functions: %s)", metric_name, region_code_type, metric_region_start, metric_region_end, str(is_fptr_pointed), contains_functions)
                    if unknown_count > 0:
                        analyzer.logger.debug("Unknowns %d / %d Overall size = %f%%", unknown_count, metric_region_size, unknown_ratio * 100)
                    if illegal_count > 0:
                        analyzer.logger.debug("Illegals %d / %d Overall size = %f%%", illegal_count, metric_region_size, illegal_ratio * 100)
                    # Check if we can flip this region
                    # 1. The entire code region is contained inside the same function, and contains unexplored bytes (not a Chunk, and contains no functions)
                    if containing_function is not None and containing_function.startEA < metric_region_start and metric_region_end <= containing_function.endEA and\
                       has_unknown_or_illegal and not contains_functions:
                        analyzer.logger.info("Code region is contained inside a single function - cancel it")
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 2. Misaligned region
                    elif not aligned_region and not code_aligned and not contains_functions:
                        analyzer.logger.info("Misaligned code region without any functions - cancel it")
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 3. Aggressive - Classifier doesn't agree about this region's start
                    elif aggressive and\
                         not aligned_region and\
                         analyzer.func_classifier.predictFunctionStartType(metric_region_start) != region_code_type and\
                         analyzer.func_classifier.predictFunctionStartType(metric_region_end)   == new_code_type and\
                         not contains_functions:
                        analyzer.logger.info("Classifier doesn't agree about the code region's start, and it has no functions - cancel it")
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 4. Aggressive - Unknowns and no functions
                    elif aggressive and\
                         has_unknown_or_illegal and not contains_functions:
                        analyzer.logger.info("Code region contains unexplored bytes, and it has no functions - fixing it")
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 5. Aggressive - pointed region that could be misinterpreted + no functions
                    elif aggressive and\
                         not aligned_region and\
                         is_fptr_pointed and\
                         prev_code_type is not None and\
                         ((not analyzer.func_classifier.predictFunctionEnd(metric_region_start, prev_code_type)) or\
                            ((metric_region_size <= analyzer.addressSize()) and not analyzer.func_classifier.predictFunctionEnd(metric_region_end,   region_code_type)) or\
                            ((metric_region_size <= analyzer.addressSize()) and not analyzer.func_classifier.predictFunctionStart(metric_region_end, new_code_type)) or\
                             analyzer.func_classifier.predictFunctionStart(metric_region_start, new_code_type)) and\
                         not contains_functions:
                        analyzer.logger.info("Code region is fptr pointed, classifier says it's not a function end, and it has no functions - cancel it")
                        # delete the fptr
                        analyzer.fptr_identifier.deleteFptr(metric_region_start, region_code_type)
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 6. Aggressive - region on function start, that could be misinterpreted + no functions
                    elif aggressive and\
                         not aligned_region and\
                         start_function is not None and metric_region_start == start_function.startEA and\
                         analyzer.func_classifier.predictFunctionStart(metric_region_start, new_code_type) and\
                         not contains_functions:
                        analyzer.logger.info("Code region is a function start, classifier prefers a different code type, and it has no functions - cancel it")
                        convertRegion(analyzer, metric_region_start, metric_region_end)
                        regions.convert(region, new_code_type)
                        region_converted = True
                        regions_fixed += 1
                    # 7. Needs a little alignment
                    elif not aligned_region and not code_aligned:
                        analyzer.logger.debug("Code region is not aligned, align it down (resize)")
                        resized_start = analyzer.alignTransitionAddress(metric_region_start, region_code_type)
                        resizeRegion(analyzer, metric_region_start, metric_region_end, resized_start, metric_region_end)
                        regions.resizeStart(region, resized_start)
                        regions_fixed += 1
                    # Nothing for now
                    else:
                        if aligned_region:
                            aligned_region_fixed = False
                        else:
                            first_metric_region_fixed = False
                    # Aligned region should start with a function
                    if aligned_region and aligned_region_fixed:
                        idc.MakeFunction(metric_region_start)
                    # Break the loop and start the new region
                    if first_metric_region_fixed:
                        break
            # if our region was converted, there is no need to scan the current region (partial data)
            dummy_mode = region_converted and first_round
            # new region - check if finished the list
            if not first_round:
                region_offset += 1
                if region_offset >= len(interesting_regions):
                    break
                # check if we need to skip the next one too
                if region_converted and region.next == interesting_regions[region_offset] and interesting_regions[region_offset].code_type == new_code_type:
                    region_offset += 1
                    if region_offset >= len(interesting_regions):
                        break
                region = interesting_regions[region_offset]
                line = sark.Line(region.start)
                region_start = line.startEA
                if region.prev is not None:
                    prev_code_type = region.prev.code_type
                else:
                    prev_code_type = None
            # the simple case
            else:
                # the code type could have changed, so we re-sample it
                if region_code_type is not None:
                    prev_code_type = analyzer.codeType(region_start)
                region_start = line.startEA
            # get the current code type (even in dummy mode)
            region_code_type = analyzer.codeType(line.startEA)
            if not dummy_mode:
                code_aligned = analyzer.isCodeTransitionAligned(region_start)
                starting_new_region = False
                # measure the metrics
                metric = CodeMetric(analyzer, region_start, measure_align=align)
                metric.start(line)
                # check if started because of one of our function pointers
                is_fptr_pointed = analyzer.fptr_identifier.isPointedFunction(region_start)
            # advance to the next line
            if first_round:
                line = line.next
        # log the result
        analyzer.logger.info("Fixed %d code regions in this iteration", regions_fixed)
        first_round = False

def negotiateRegions(analyzer, sc):
    """Try and negotiate over the exact transition point between each two regions.

    Args:
        analyzer (instance): analyzer instance to be used
        sc (segment): (sark) code segment to work on
    """
    starting_new_region = True  # edge case for the first line in the section
    region_code_type = None
    region_start = 0
    for line in sc.lines:
        if not starting_new_region:
            # check if we found a transitions
            new_code_type = analyzer.codeType(line.startEA)
            # no change, just keep on
            if region_code_type == new_code_type:
                continue
            # we found a transition
            region_end = line.startEA
            # check if we can shorten our region (expand the newly found region)
            fixed_region_end = region_end
            # Case #1 - Previous line has no xrefs, and isn't code (must be aligned, and must not be a switch table entry)
            prev_line = line.prev
            crefs_to_prev = list(prev_line.crefs_to)
            drefs_to_prev = list(prev_line.drefs_to)
            if not analyzer.switch_identifier.isSwitchEntry(prev_line.startEA) and\
               not prev_line.is_code and len(crefs_to_prev) + len(drefs_to_prev) == 0 and analyzer.isCodeTransitionAligned(prev_line.startEA):
                fixed_region_end = prev_line.startEA
            # The region start case was fixed during the function scan :)
            # preform the action
            if fixed_region_end < region_end:
                resizeRegion(analyzer, region_start, region_end, region_start, fixed_region_end)
            # Fall through - we started a new region

        # mark that we started a new region
        region_start = line.startEA
        region_code_type = analyzer.codeType(line.startEA)
        starting_new_region = False

def resolveFunctionChunks(analyzer, scs):
    """Resolve all of the (external) function chunks that we can manage.

    Args:
        analyzer (instance): analyzer instance to be used
        scs (list): list of (sark) code segments
    """
    seen_candidates = defaultdict(int)
    for sc in scs:
        for function in sc.functions:
            outer_blocks = []
            for block in idaapi.FlowChart(function.func_t):
                if block.endEA < function.startEA or function.endEA <= block.startEA:
                    try:
                        block_function = sark.Function(block.startEA)
                    except sark.exceptions.SarkNoFunction:
                        block_function = None
                    # Only interested in chunks which are not already functions
                    if block_function is None or block_function.startEA != block.startEA:
                        outer_blocks.append(block)
                    # Function chunks which are switch cases, should be fixed
                    elif block_function is not None and analyzer.switch_identifier.isSwitchCase(block.startEA):
                        analyzer.logger.debug("Deleted switch case function: 0x%x", block.startEA)
                        idc.del_func(block.startEA)
                        outer_blocks.append(block)
            # check if there is something to scan
            if len(outer_blocks) == 0:
                continue
            # start by resetting the function
            idc.del_func(function.startEA)
            idc.MakeFunction(function.startEA)
    # Now try to check for chunks
    for sc in scs:
        for function in sc.functions:
            outer_blocks = []
            for block in idaapi.FlowChart(function.func_t):
                if block.endEA < function.startEA or function.endEA <= block.startEA:
                    try:
                        block_function = sark.Function(block.startEA)
                    except sark.exceptions.SarkNoFunction:
                        block_function = None
                    # Only interested in chunks which are not already functions
                    if block_function is None or block_function.startEA != block.startEA:
                        outer_blocks.append(block)
                    # Function chunks which are switch cases, should be fixed
                    elif block_function is not None and analyzer.switch_identifier.isSwitchCase(block.startEA):
                        analyzer.logger.debug("Deleted switch case function: 0x%x", block.startEA)
                        idc.del_func(block.startEA)
                        outer_blocks.append(block)
            # check if there is something to scan
            if len(outer_blocks) == 0:
                continue
            # scan the block for connectivity groups
            connectivity_mapping = {}
            connectivity_id = 0
            id_mappings = {}
            for block in outer_blocks:
                if block.startEA not in connectivity_mapping:
                    connectivity_mapping[block.startEA] = connectivity_id
                    id_mappings[connectivity_id] = connectivity_id
                    connectivity_id += 1
                cur_id = connectivity_mapping[block.startEA]
                for succs in block.succs():
                    # if unmarked, add him to our group
                    if succs.startEA not in connectivity_mapping:
                        connectivity_mapping[succs.startEA] = cur_id
                    # if marked, set our group ID to match his group ID (effectively using the minimal ID)
                    else:
                        id_mappings[cur_id] = id_mappings[connectivity_mapping[succs.startEA]]
            # Now pick the minimal candidate of each connectivity group
            group_candidate_mapping = {}
            for block in outer_blocks:
                cur_id = id_mappings[connectivity_mapping[block.startEA]]
                if cur_id not in group_candidate_mapping:
                    group_candidate_mapping[cur_id] = block.startEA
                else:
                    group_candidate_mapping[cur_id] = min(block.startEA, group_candidate_mapping[cur_id])
            # Now fix mis-analysed switch cases
            original_start = function.startEA
            original_end = function.endEA
            tentative_func_end = original_end
            for cur_id, candidate in group_candidate_mapping.items():
                seen_candidates[candidate] += 1
                # Handle the switch cases
                if analyzer.switch_identifier.isSwitchCase(candidate):
                    tentative_func_end = max(tentative_func_end, candidate)
            # check if we had a switch case outside of our function
            if tentative_func_end > original_end:
                # scan the range and delete each function in it
                for offset in xrange(tentative_func_end - original_end):
                    try:
                        func = sark.Function(original_end + offset)
                        if func.endEA != original_end:
                            idc.del_func(func.startEA)
                            analyzer.logger.debug("Deleted function at: 0x%x", func.endEA)
                    except sark.exceptions.SarkNoFunction:
                        pass
                # now re-define the original function
                analyzer.logger.debug("Re-defined the (switch) function at: 0x%x", original_start)
                idc.del_func(original_start)
                idc.MakeFunction(original_start)
                # can move on to the next function
                continue
            # Each candidate should be a function on it's own (unless it is already contained in another function)
            for cur_id, candidate in group_candidate_mapping.items():
                idc.del_func(original_start)
                external_func = None
                contained_chunk = False
                # Check what happens when the candidate is adjacent to the end of the function
                if candidate == original_end:
                    idc.del_func(candidate)
                    contained_chunk = True
                else:
                    # candidate might be inside a different function
                    try:
                        func = sark.Function(candidate)
                        # If our chunk is the legit ending of a given function, don't ruin it
                        contained_chunk = func.startEA <= candidate and candidate < func.endEA
                        if func.startEA != original_start and not contained_chunk:
                            external_func = func.startEA
                            idc.del_func(func.startEA)
                    except sark.exceptions.SarkNoFunction:
                        pass
                # Should the chunk be a standalone function?
                if not contained_chunk:
                    idc.MakeFunction(candidate)
                # Restore the original function
                idc.MakeFunction(original_start)
                # If needed, restore the external (container) function
                if external_func is not None:
                    idc.MakeFunction(external_func)
                analyzer.logger.debug("Re-defined the function at: 0x%x, candidate at: 0x%x", original_start, candidate)
