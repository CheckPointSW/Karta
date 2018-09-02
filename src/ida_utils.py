from utils   import *
from ida_api import *

def analyzeFunctionGraph(func_ea, src_mode) :
    """Analyzes the flow graph of a given function, generating a call-order mapping
    
    Args:
        func_ea (int): effective address of the wanted function
        src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

    Return Value:
        A dictionary representing the the list of function calls that lead to a specific function call: call ==> list of preceding calls
    """
    block_to_ref   = {}
    ref_to_block   = {}
    ref_to_call    = {}
    block_to_reach = {}
    call_to_reach  = {}
    # 1st scan, build up the mappings - O(N) time, O(k) storage
    func = sark.Function(func_ea)
    func_start = func.startEA
    flow = idaapi.FlowChart(func.func_t)
    for block in flow :
        block_to_reach[block.start_ea] = set()
        try :
            block_lines = sark.CodeBlock(block.start_ea).lines
        except :
            continue
        for line in block_lines :
            instr_pos = line.ea
            call_candidates = set()
            # Data Refs (strings, fptrs)
            for ref in line.drefs_from :
                # Check for a string (finds un-analyzed strings too)
                str_const = idc.GetString(ref, -1, -1)
                if str_const is not None and len(str_const) >= MIN_STR_SIZE :
                    continue
                # Check for an fptr
                try :
                    call_candidates.add(sark.Function(ref).startEA)
                except :
                    continue
            # Check for a function call
            for cref in line.crefs_from :
                try :
                    if (cref == func_start and line.insn.is_call) or sark.Function(cref).startEA != func_start :
                        call_candidates.add(sark.Function(cref).startEA)
                except Exception, e:
                    continue
            # handle each ref (beware of unknowns)
            for ref in call_candidates :
                call = sark.Function(ref)
                # Make sure it is not an unknown
                if src_mode and sark.Line(ref).disasm.startswith("extrn ") :
                    continue
                # record the call
                if block.start_ea not in block_to_ref :
                    block_to_ref[block.start_ea] = set()
                block_to_ref[block.start_ea].add(instr_pos)
                ref_to_block[instr_pos] = block
                ref_to_call[instr_pos] = call.name if src_mode else call.startEA

    # 2nd scan, start from each reference, and propagate till the end - O(kN), E(N) time, O(N) storage
    sorted_refs = ref_to_block.keys()
    sorted_refs.sort()
    for ref in sorted_refs :
        start_block = ref_to_block[ref]
        working_set = set([ref])
        # we distinguish between refs even on the same block, no need to search for them because we scan using sorted_refs
        # mark the start block
        block_to_reach[start_block.start_ea].add(ref)
        # check if we can stop now
        if len(block_to_ref[start_block.start_ea]) > 1 and ref != max(block_to_ref[start_block.start_ea]) :
            continue
        # carry on the tasks that were leftover by previous references
        working_set.update(block_to_reach[start_block.start_ea])
        # build a list of BFS nodes
        search_list = map(lambda x : (x, set(working_set)), start_block.succs())
        seen_blocks = set()
        # BFS Scan - until the list is empty
        while len(search_list) > 0 :
            new_search_list = []
            for cur_block, working_set in search_list :
                # check for loops
                if cur_block.start_ea in seen_blocks and len(block_to_reach[cur_block.start_ea].difference(working_set)) == 0 :
                    continue
                # mark as seen
                seen_blocks.add(cur_block.start_ea)
                # always mark it
                block_to_reach[cur_block.start_ea].update(working_set)
                # if reached a starting block of a lesser reference, tell him to keep on for us
                if cur_block.start_ea in block_to_ref and max(block_to_ref[cur_block.start_ea]) > cur_block.start_ea :
                    # we can stop :)
                    continue
                # learn, and keep going
                else :
                    working_set.update(block_to_reach[cur_block.start_ea])
                    new_search_list += map(lambda x : (x, set(working_set)), cur_block.succs())
            search_list = new_search_list

    # 3rd scan, sum up the results - O(k) time, O(k*k) storage
    for ref in ref_to_block.keys() :
        reachable_from = block_to_reach[ref_to_block[ref].start_ea]
        # add a filter to prevent collisions from the same block
        reachable_from = reachable_from.difference(filter(lambda x : x > ref, block_to_ref[ref_to_block[ref].start_ea]))
        if ref_to_call[ref] not in call_to_reach :
            call_to_reach[ref_to_call[ref]] = []
        current_record = set(filter(lambda x : x != ref_to_call[ref], map(lambda x : ref_to_call[x], reachable_from)))
        if current_record not in call_to_reach[ref_to_call[ref]] :
            call_to_reach[ref_to_call[ref]].append(list(current_record))

    # return the results
    return call_to_reach

def analyzeFunction(func_ea, src_mode) :
    """Analyze a given function, and creates a canonical representation for it
    
    Args:
        func_ea (int): effective address of the wanted function
        src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

    Return Value:
        FunctionContext object representing the analyzed function
    """
    func = sark.Function(func_ea)
    context = FunctionContext(func.name, func_ea)
    
    func_start = func.startEA
    instr_count = 0
    call_candidates = set()
    for line in func.lines :
        instr_count += 1
        # Numeric Constants
        data_refs = list(line.drefs_from)
        for oper in filter(lambda x : x.type.is_imm, line.insn.operands) :
            if oper.imm not in data_refs :
                context.recordConst(oper.imm)
        # Data Refs (strings, fptrs)
        for ref in data_refs :
            # Check for a string (finds un-analyzed strings too)
            str_const = idc.GetString(ref, -1, -1)
            if str_const is not None and len(str_const) >= MIN_STR_SIZE :
                context.recordString(str_const)
                continue
            # Check for an fptr
            try :
                call_candidates.add(sark.Function(ref).startEA)
            except Exception, e:
                continue
        # Code Refs (calls and unknowns)
        for cref in line.crefs_from :
            try :
                if (cref == func_start and line.insn.is_call) or sark.Function(cref).startEA != func_start :
                    call_candidates.add(sark.Function(cref).startEA)
            except Exception, e:
                continue
        # in binary mode don't let the call_candidates expand too much
        if not src_mode :
            map(lambda x : context.recordCall(x), call_candidates)
            call_candidates = set()

    # check all the call candidates together
    if src_mode :
        for candidate in call_candidates :
            ref_func = sark.Function(candidate)
            # check if known or unknown
            if sark.Line(ref).disasm.startswith("extrn ") :
                context.recordUnknown(ref_func.name)
            else :
                context.recordCall(ref_func.name)

    context.setFrame(func.frame_size)
    context.setInstrCount(instr_count)

    # Now, record the code blocks
    flow = idaapi.FlowChart(func.func_t)
    for block in flow :
        try :
            context.recordBlock(len(list(sark.CodeBlock(block.start_ea).lines)))
        except :
            # happens with code outside of a function
            continue
    context._blocks.sort(reverse = True)

    # Now add the flow analysis
    context.setCallOrder(analyzeFunctionGraph(func_ea, src_mode))

    return context

def searchIslands(func_ea, range_start, range_end) :
    """Search a given function for "Islands" from a specific code range
    
    Args:
        func_ea (int): effective address of the wanted function
        range_start (int): effective address of the start of the island range
        range_end (int): effective address of the end of the island range

    Return Value:
        Orderred list of code blocks for the found island, or None if found nothing
    """
    island_guess = None
    func = sark.Function(func_ea)
    flow = idaapi.FlowChart(func.func_t)
    for block in flow :
        if range_start <= block.start_ea and block.end_ea <= range_end :
            if island_guess is None or block.start_ea < island_guess.start_ea :
                island_guess = block
    # quit if found nothing
    if island_guess is None :
        return None
    # make sure that the island is indeed an island, and not a well known function
    if sark.Function(island_guess.start_ea).startEA == island_guess.start_ea :
        return None
    # find the contained flow, that island_guess is the start of
    island_blocks = []
    candidate_list = [island_guess]
    while len(candidate_list) != 0 :
        new_candidate_list = []
        for candidate_block in candidate_list :
            if candidate_block in island_blocks :
                continue
            island_blocks.append(candidate_block)
            new_candidate_list += filter(lambda succs : range_start <= succs.start_ea and succs.end_ea <= range_end, candidate_block.succs())
        candidate_list = new_candidate_list
    # return the results  
    return island_blocks

def analyzeIslandFunction(blocks) :
    """Analyze a given island function, and creates a canonical representation for it
    
    Args:
        blocks (list): orderred list of code blocks (as returned from searchIslands())

    Return Value:
        IslandContext object representing the analyzed island
    """
    island_start = blocks[0].start_ea
    func = sark.Function(island_start)
    func_start = func.startEA
    context = IslandContext(func.name, island_start)
    for block in blocks :
        for line in sark.CodeBlock(block.start_ea).lines :
            # Numeric Constants
            data_refs = list(line.drefs_from)
            for oper in filter(lambda x : x.type.is_imm, line.insn.operands) :
                if oper.imm not in data_refs :
                    context.recordConst(oper.imm)
                    context._const_ranks[oper.imm] = rankConst(oper.imm, None)
            # Data Refs (strings, fptrs)
            for ref in data_refs :
                # Check for a string (finds un-analyzed strings too)
                str_const = idc.GetString(ref, -1, -1)
                if str_const is not None and len(str_const) >= MIN_STR_SIZE :
                    context.recordString(str_const)
                    continue
                # Check for an fptr
                try :
                    context.recordCall(sark.Function(ref).startEA)
                except :
                    continue
            # Code Refs (calls)
            for cref in line.crefs_from :
                try :
                    if (cref == func_start and line.insn.is_call) or sark.Function(cref).startEA != func_start :
                        context.recordCall(sark.Function(cref).startEA)
                except Exception, e:
                    continue

    return context

def locateAnchorConsts(func_ea, const_set) :
    """Analyzes the function in search for specific immediate numerics

    Args:
        func_ea (int): effective address of the analyzed function
        const_set (set): set of numeric consts to search for as immediate values
    
    Return Value :
        a set that contains the matched immediate value, an empty set if found none)
    """
    results = set()
    for line in sark.Function(func_ea).lines :
        # Numeric Constants
        data_refs = list(line.drefs_from)
        for oper in filter(lambda x : x.type.is_imm, line.insn.operands) :
            if oper.imm in const_set and oper.imm not in data_refs :
                results.add(oper.imm)
    return results
