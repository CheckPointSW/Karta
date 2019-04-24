import idaapi
import sark
from config.utils   import *
from hashlib        import md5

class AnalyzerIDA(object):
    """Logic instance for the IDA disassembler API. Contains the heart of Karta's canonical representation.

    Note
    ----
        Contains specific Karta logic.

    Attributes
    ----------
        disas (disassembler): disassembler layer instance
    """

    def __init__(self, disas):
        """Prepare the analyzer.

        Args:
            disas (disassembler): disassembler layer instance
        """
        self.disas = disas

    def funcNameInner(self, raw_func_name):
        """Return the name of the function (including windows name fixes).

        Args:
            raw_func_name (str): raw string func name

        Return Value:
            The actual (wanted) name of the wanted function
        """
        base_name = raw_func_name
        # check for the libc edge case
        if isWindows() and (not isMatching()) and base_name.startswith("__imp_"):
            base_name = base_name[len("__imp_"):]
        if isWindows() and (not isMatching()) and base_name.startswith("_"):
            return base_name[1:]
        else:
            return base_name

    def funcNameEA(self, func_ea):
        """Return the name of the function that was defined in the given address (including windows name fixes).

        Args:
            func_ea (int): effective address of the wanted function

        Return Value:
            The actual (wanted) name of the wanted function
        """
        func = self.disas.funcAt(func_ea)
        if func is not None:
            return self.funcNameInner(func.name)
        return self.funcNameInner(self.disas.nameAt(func_ea))

    def analyzeFunctionBlock(self, block_ea):
        """Return pairs indicating function calls (or fptr refs) from the lines in the basic block instance.

        Args:
            block_ea (int): basic block ea

        Return Value:
            (ordered) list of tuples: [<address of function ref (src), referenced address of the function (dest)>, ]
        """
        function_calls = []
        try:
            func_start = sark.Function(block_ea).startEA
            block_lines = sark.CodeBlock(block_ea).lines
        except Exception:
            return function_calls
        # scan each of the lines
        for line in block_lines:
            instr_pos = line.ea
            call_candidates = set()
            # Data Refs (strings, fptrs)
            for ref in line.drefs_from:
                # Check for a string (finds un-analyzed strings too)
                str_const = self.disas.stringAt(ref)
                if str_const is not None and len(str_const) >= MIN_STR_SIZE:
                    continue
                # Check for an fptr
                try:
                    call_candidates.add(sark.Function(ref).startEA)
                except sark.exceptions.SarkNoFunction:
                    continue
            # Check for a function call
            for cref in line.crefs_from:
                try:
                    if (cref == func_start and line.insn.is_call) or sark.Function(cref).startEA != func_start:
                        call_candidates.add(sark.Function(cref).startEA)
                except sark.exceptions.SarkNoFunction:
                    continue
            # handle each ref
            for ref in call_candidates:
                # record the call
                function_calls.append((instr_pos, sark.Function(ref).startEA))
        # return the result
        return function_calls

    def analyzeFunction(self, func_ea, src_mode):
        """Analyze a given function, and creates a canonical representation for it.

        Args:
            func_ea (int): effective address of the wanted function
            src_mode (bool): True iff analyzing a self-compiled source file, otherwise analyzing a binary function

        Return Value:
            FunctionContext object representing the analyzed function
        """
        func = sark.Function(func_ea)
        if src_mode:
            context = sourceContext()(self.funcNameInner(func.name), 0)  # Index is irrelevant for the source analysis
        else:
            context = binaryContext()(func_ea, self.funcNameInner(func.name), 0)  # The index will be adjusted later, manually

        func_start = func.startEA
        instr_count = 0
        call_candidates = set()
        code_hash = md5()
        for line in func.lines:
            instr_count += 1
            # Numeric Constants
            data_refs = list(line.drefs_from)
            for oper in filter(lambda x: x.type.is_imm, line.insn.operands):
                if oper.imm not in data_refs:
                    context.recordConst(oper.imm)
            # Data Refs (strings, fptrs)
            for ref in data_refs:
                # Check for a string (finds un-analyzed strings too)
                str_const = self.disas.stringAt(ref)
                if str_const is not None and len(str_const) >= MIN_STR_SIZE:
                    context.recordString(str_const)
                    continue
                # Check for an fptr
                called_func = self.disas.funcAt(ref)
                if called_func is not None:
                    call_candidates.add(self.disas.funcStart(called_func))
                elif src_mode:
                    call_candidates.add(ref)
                    continue
            # Code Refs (calls and unknowns)
            for cref in line.crefs_from:
                called_func = self.disas.funcAt(cref)
                if called_func is None:
                    continue
                called_func_start = self.disas.funcStart(called_func)
                if (cref == func_start and line.insn.is_call) or called_func_start != func_start:
                    call_candidates.add(called_func_start)
            # in binary mode don't let the call_candidates expand too much
            if not src_mode:
                map(lambda x: context.recordCall(x), call_candidates)
                call_candidates = set()
            # hash the instruction (only in source mode)
            else:
                # two cases:
                # 1. No linker fixups, hash the binary - easy case
                # 2. Linker fixups, hash the text (includes the symbol name that the linker will use too)
                has_fixups = False
                # data variables
                for dref in line.drefs_from:
                    if sark.Line(dref).name in self.disas.exports():
                        has_fixups = True
                        break
                # external code functions
                if not has_fixups:
                    for cref in line.crefs_from:
                        if sark.Line(cref).name in self.disas.exports():
                            has_fixups = True
                            break
                # case #2
                if has_fixups:
                    code_hash.update(line.disasm)
                # case #1
                else:
                    code_hash.update(line.bytes)

        # check all the call candidates together
        if src_mode:
            for candidate in call_candidates:
                ref_func = None
                called_func = self.disas.funcAt(candidate)
                if called_func is not None:
                    ref_func = self.disas.funcName(called_func)
                    risky = False
                else:
                    ref_func = self.disas.nameAt(candidate)
                    risky = True
                # check if known or unknown
                if sark.Line(candidate).disasm.split(" ")[0].lower() in ("extrn", "extern", "import"):
                    context.recordUnknown(ref_func, is_fptr=risky)
                elif not risky:
                    context.recordCall(ref_func)
            # set the function's hash
            context.setHash(code_hash.hexdigest())

        context.setFrame(func.frame_size)
        context.setInstrCount(instr_count)

        # Now, record the code blocks
        flow = idaapi.FlowChart(func.func_t)
        for block in flow:
            try:
                context.recordBlock(len(list(sark.CodeBlock(block.startEA).lines)))
            except Exception:
                # happens with code outside of a function
                continue
        context.blocks.sort(reverse=True)

        # Now add the flow analysis
        context.setCallOrder(self.disas.analyzeFunctionGraph(func_ea, src_mode))

        return context

    def searchIslands(self, func_ea, range_start, range_end):
        """Search a given function for "Islands" from a specific code range.

        Args:
            func_ea (int): effective address of the wanted function
            range_start (int): effective address of the start of the island range
            range_end (int): effective address of the end of the island range

        Return Value:
            Ordered list of code blocks for the found island, or None if found nothing
        """
        island_guess = None
        func = sark.Function(func_ea)
        flow = idaapi.FlowChart(func.func_t)
        for block in flow:
            if range_start <= block.startEA and block.endEA <= range_end:
                if island_guess is None or block.startEA < island_guess.startEA:
                    island_guess = block
        # quit if found nothing
        if island_guess is None:
            return None
        # make sure that the island is indeed an island, and not a well known function
        if sark.Function(island_guess.startEA).startEA == island_guess.startEA:
            return None
        # find the contained flow, that island_guess is the start of
        island_blocks = []
        candidate_list = [island_guess]
        while len(candidate_list) != 0:
            new_candidate_list = []
            for candidate_block in candidate_list:
                if candidate_block in island_blocks:
                    continue
                island_blocks.append(candidate_block)
                new_candidate_list += filter(lambda succs: range_start <= succs.startEA and succs.endEA <= range_end, candidate_block.succs())
            candidate_list = new_candidate_list
        # return the results
        return island_blocks

    def analyzeIslandFunction(self, blocks):
        """Analyze a given island function, and creates a canonical representation for it.

        Args:
            blocks (list): ordered list of code blocks (as returned from searchIslands())

        Return Value:
            IslandContext object representing the analyzed island
        """
        island_start = blocks[0].startEA
        func = sark.Function(island_start)
        func_start = func.startEA
        context = islandContext()(self.funcNameInner(func.name), island_start)
        for block in blocks:
            for line in sark.CodeBlock(block.startEA).lines:
                # Numeric Constants
                data_refs = list(line.drefs_from)
                for oper in filter(lambda x: x.type.is_imm, line.insn.operands):
                    if oper.imm not in data_refs:
                        context.recordConst(oper.imm)
                # Data Refs (strings, fptrs)
                for ref in data_refs:
                    # Check for a string (finds un-analyzed strings too)
                    str_const = self.disas.stringAt(ref)
                    if str_const is not None and len(str_const) >= MIN_STR_SIZE:
                        context.recordString(str_const)
                        continue
                    # Check for an fptr
                    called_func = self.disas.funcAt(ref)
                    if called_func is not None:
                        context.recordCall(self.disas.funcStart(called_func))
                # Code Refs (calls)
                for cref in line.crefs_from:
                    called_func = self.disas.funcAt(cref)
                    if called_func is None:
                        continue
                    called_func_start = self.disas.funcStart(called_func)
                    if (cref == func_start and line.insn.is_call) or called_func_start != func_start:
                        context.recordCall(called_func_start)

        return context

    def locateAnchorConsts(self, func_ea, const_set):
        """Analyze the function in search for specific immediate numerics.

        Args:
            func_ea (int): effective address of the analyzed function
            const_set (set): set of numeric consts to search for as immediate values

        Return Value:
            a set that contains the matched immediate value, an empty set if found none)
        """
        results = set()
        for line in sark.Function(func_ea).lines:
            # Numeric Constants
            data_refs = list(line.drefs_from)
            for oper in filter(lambda x: x.type.is_imm, line.insn.operands):
                if oper.imm in const_set and oper.imm not in data_refs:
                    results.add(oper.imm)
        return results

    def stringsInFunc(self, func_ea):
        """Analyze the function in search for all referenced strings.

        Args:
            func_ea (int): effective address of the analyzed function

        Return Value :
            a *list* that contains all of the referenced strings (including duplicates)
        """
        results = []
        for line in sark.Function(func_ea).lines:
            # String Constants
            data_refs = list(line.drefs_from)
            for ref in data_refs:
                # Check for a string (finds un-analyzed strings too)
                str_const = self.disas.stringAt(ref)
                if str_const is not None and len(str_const) >= MIN_STR_SIZE:
                    results.append(str_const)
        return results
