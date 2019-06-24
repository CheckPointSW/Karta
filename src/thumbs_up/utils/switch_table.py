import pickle
import idc
import idaapi
import sark
from pattern_observer import AlignmentPattern, CodePattern, pad

###########################
## Static Configurations ##
###########################

# Default path for storing the state of the observed switch table meta-data (used mainly for debugging)
switch_case_entries_path = "switch_cases.bin"

class SwitchIdentifier():
    """An Identifier class for switch-table related features.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _table_alignment (int): byte-alignment of the switch tables inside our functions
        _code_pattern (pattern): CodePattern instance of the observed code pattern before each switch table
        _record_size (int): default record size for a switch table entry to be identified
        _switch_case_entries (list): list of features from observed switch cases: (line.startEA, table_start ea, table_end ea)
        _switch_case_cases (list): list of all observed switch table entries, from all tables (cleaned code addresses)

    Notes
    -----
        1. The logic currently only works well for ARM pointer-sized switch tables.
        2. Should make sure it will work good enough for other architectures as well
    """

    def __init__(self, analyzer):
        """Create a switch identifier instance.

        Args:
            analyzer (instance): analyzer instance to be linked against
        """
        self._analyzer = analyzer
        self._record_size = self._analyzer.addressSize()
        self._table_alignment = None
        self._code_pattern    = None
        # set up the globals
        self._switch_case_entries = []
        self._switch_case_cases   = []

    def store(self):
        """Store the collected switch table features into a backup file (used mainly for debugging)."""
        fd = open(switch_case_entries_path, "wb")
        pickle.dump(self._switch_case_entries, fd)
        fd.close()

    def load(self):
        """Load the collected switch tables features from a previous execution (used mainly for debugging).

        Return Value:
            True iff successfully loaded the meta-data
        """
        try:
            switch_case_entries = pickle.load(open(switch_case_entries_path, "rb"))
            for switch_instr, table_start, table_end in switch_case_entries:
                for ea in xrange(table_start, table_end, self._analyzer.addressSize()):
                    self._switch_case_cases.append(self._analyzer.cleanPtr(self._analyzer.parseAdderss(ea)))
            return True
        except Exception:
            self._switch_case_entries = []
            self._switch_case_cases   = []
            return False

    def markSwitchTables(self, sc, aggressive=True):
        """Help IDA by marking all of the needed information from the observed switch tables.

        Args:
            sc (segment): (sark) code segment in which we are interested right now
            aggressive (bool, optional): True iff the marking operation should be aggressive, see notes. (True by default)

        Notes
        -----
            1. Make sure the switch case jump instruction is indeed a code line
            2. Make sure the jump instruction has a code reference to all of the switch cases
            3. (Aggressive) Make sure each switch table entry is a proper code pointer to it's matching case
            4. (Aggressive) Enforce the correct code type over the entire gap between the minimal and maximal case
        """
        for switch_instr, table_start, table_end in filter(lambda x: sc.startEA <= x[0] and x[1] < sc.endEA, self._switch_case_entries):
            cases = []
            if not sark.Line(switch_instr).is_code:
                idc.MakeUnknown(switch_instr, self._analyzer.addressSize(), 0)
                idc.MakeCode(switch_instr)
            for ea in xrange(table_start, table_end, self._analyzer.addressSize()):
                entry = self._analyzer.parseAdderss(ea)
                if aggressive:
                    self._analyzer.markCodePtr(ea, entry)
                fixed_entry = self._analyzer.cleanPtr(entry)
                cases.append(fixed_entry)
                idc.add_cref(switch_instr, fixed_entry, idc.XREF_USER | idc.dr_O)
            if aggressive:
                self._analyzer.setCodeType(min(cases), max(cases), self._analyzer.ptrCodeType(entry))

    def isSwitchEntry(self, ea):
        """Check if the given address fits inside a seen switch table.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is contained inside a seen switch table
        """
        return len(filter(lambda x: x[0] <= ea and ea < x[1], self._switch_case_entries)) != 0

    def isSwitchCase(self, ea):
        """Check if the given address is the beginning of a seen switch case.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address matches the beginning of a seen switch case
        """
        return ea in self._switch_case_cases

    def observeSwitchTableFeatures(self, scs):
        """Observe the features of IDA-recognized switch tables, and try to detect patterns.

        Args:
            scs (list): list of (sark) code segments

        Notes
        -----
            1. Trying to observe an alignment pattern for the switch tables.
            2. Trying to observe a code pattern for the instruction before each switch table.

        Return Value:
            True iff found all of the desired features (patterns)
        """
        table_alignment_pattern = AlignmentPattern()
        observer = CodePattern()
        for sc in scs:
            # scan for known switch cases, and only from our desired record size
            for line in filter(lambda x: x.is_code, sc.lines):
                try:
                    sw = idaapi.get_switch_info_ex(line.startEA)
                    if sw is None:
                        continue
                    if sw.get_jtable_element_size() != self._record_size:
                        continue
                    # The table should be near our code (otherwise we don't care about it)
                    if abs(line.startEA - sw.jumps) > 0x100:
                        continue
                except Exception:
                    continue
                # IDA recognized the switch table exactly at the last code instruction before it
                observer.add(line)

                # Going to use the easy case
                # 1. Find the table alignment (4)
                # 2. Find the command + common args for the jump line (MOV PC, )
                # 3. Assume the table is right after this command, padded to alignment
                # 4. Count the cases as long as they point to code near us
                # 5. Don't define it as a switch table using IDA's structures (too complex)
                self._analyzer.logger.debug("Located a switch table at: 0x%x", line.startEA)
                self._analyzer.logger.debug("\tStart EA: 0x%x", sw.startea)
                self._analyzer.logger.debug("\tJump Table: 0x%x", sw.jumps)
                self._analyzer.logger.debug("\t%s", str(line))
                # table alignment
                table_alignment_pattern.add(sw.jumps)

        # check if found any
        if table_alignment_pattern.size() < 2:
            self._analyzer.logger.error("Couldn't find enough switch tables in this code section...")
            return False

        # print all of the statistics
        self._analyzer.logger.info("Switch Table Results:")
        self._table_alignment = table_alignment_pattern.decide()
        self._analyzer.logger.info("Table alignment is: %d", self._table_alignment)

        if not observer.decide():
            self._analyzer.logger.error("Failed to find any code pattern for the switch tables")
            return False
        else:
            self._analyzer.logger.info("Switch jump code instruction is: %s", observer)
            self._code_pattern = observer
            return True

    def predictSwitchStart(self, line):
        """Predict if the given code line matches a switch's jump instruction.

        Args:
            line (line): (sark) code line

        Return Value:
           True iff the given code line matches the observed pattern for switch jump instructions
        """
        return self._code_pattern.query(line)

    def locateSwitchTables(self, scs):
        """Locate all of the switch tables in the set of code segments.

        Args:
            scs (list): list of (sark) code segments
        """
        table_candidates = []
        for sc in scs:
            # code segments & functions
            for line in filter(lambda x: x.is_code, sc.lines):
                # can fail when near a thumb register mess
                try:
                    # check for a switch start
                    if not self.predictSwitchStart(line):
                        continue
                except Exception:
                    continue
                # Sadly, it seems that we need to fix even some of the known switch tables
                table_candidates.append((line, pad(line.endEA, self._table_alignment)))

        # now check all of the candidates
        counter = 0
        for line, table_start in table_candidates:
            is_table = True
            cur_ea = table_start
            code_type = None
            cases = []
            # table could contain entries that have our 2 MSBs + [0,1,2,3]
            entry_options = map(lambda x: ((0xFFFF0000 & table_start) >> 16) + x, range(4))
            while is_table:
                entry = self._analyzer.parseAdderss(cur_ea)
                cur_ea += self._analyzer.addressSize()
                # The 2 MSBs should points us to the surroundings of our code area
                is_table = ((0xFFFF0000 & entry) >> 16) in entry_options
                # save the entry (mask the THUMB bit)
                cases.append(self._analyzer.cleanPtr(entry))
                if code_type is None:
                    code_type = self._analyzer.ptrCodeType(entry)
            # reduce back the wrong entry guess that we've read
            cur_ea -= self._analyzer.addressSize()
            cases = cases[:-1]
            # if we found nothing, do nothing
            if len(cases) == 0:
                continue
            table_end = cur_ea
            self._analyzer.logger.debug("Found a Switch Table at: 0x%x - 0x%x (0x%x entries) - (%d code type)", table_start, table_end, len(cases), code_type)
            counter += 1
            # record the info
            self._switch_case_entries.append((line.startEA, table_start, table_end))

        # mark all of the tables
        self.markSwitchTables(sc, aggressive=True)
        self._analyzer.logger.info("Found %d switch tables", counter)

#############################################################################################
## This comments store useful API for IDA's switch tables - we might need it in the future ##
#############################################################################################

# switch_info = idaapi.switch_info_ex_t()
# # # find the exact start
# line = start_line
# start_ea = line.startEA
# defjump = None
# for i in xrange(10):
#     if line.is_code and line.insn.mnem == 'CMP' and list(line.insn.operands)[1].value + 1 == len(cases):
#         start_ea = line.startEA
#         defjump = list(line.next.insn.operands)[0].offset
#         print 'Switch details: start_ea = 0x%x, default jump = 0x%x' % (start_ea, defjump)
#         break
#     line = line.prev
# idaapi.switch_info_ex_t_set_startea(switch_info, start_ea)
# idaapi.switch_info_ex_t_set_ncases(switch_info, len(cases))
# idaapi.switch_info_ex_t_set_jumps(switch_info, table_start)
# switch_info.set_jtable_element_size(4)
# if defjump is not None:
#     switch_info.defjump = defjump
#     # died in IDA 7.0
#     try:
#         switch_info.flags |= idaapi.SWI_DEFAULT
#     except:
#         pass
# # Make sure IDA had no problems with it
# idc.MakeUnknown(table_start, cur_offset - table_start, 0)
# for addr in xrange(table_start / 4, cur_offset / 4):
#     addr = addr * 4
#     ida_offset.op_offset(addr, 0, idc.REF_OFF32)
#     switch_offset_entries.add(addr)
# # actually create the switch table
# idaapi.create_switch_table(start_ea, switch_info)

# sw.jumps => address of jump table
# sw.defjump => address of default case
# sw.elbase => 0 if no padding for table, otherwise ???
# sw.get_jtable_element_size() => size of table records
# sw.get_jtable_size() => number of records in the table
# sw.get_lowcase() => minimal switch case value
# sw.get_shift() => switch case shift value
# sw.has_default() => is there a default case
# sw.has_elbase() => is there a elbase
# sw.regnum => number of the switch register (could be turned into a mapping for id <=> string)
# sw.startea => address of the first instruction of the switch case => the compare
