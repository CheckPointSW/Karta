from disassembler.disas_api import DisasCMD
from disassembler.factory   import registerDisassemblerCMD
import os

class IdaCMD(DisasCMD):
    """DisasCMD implementation for the IDA disassembler"""

    # Overriden base function
    @staticmethod
    def identify(path):
        return os.path.split(path)[-1].split('.')[0].lower().startswith("ida")

    # Overriden base function
    @staticmethod
    def name():
        return "IDA"

    # Overriden base function
    def createDatabase(self, binary_file, is_windows):
        type = "elf" if not is_windows else "coff"
        suffix = ".i64" if self._path.endswith("64") else ".idb"
        # execute the prorgam
        os.system("%s -A -B -T%s %s" % (self._path, type, binary_file))
        # return back the (should be) created database file path
        return binary_file + suffix

    # Overriden base function
    def executeScript(self, database, script):
        os.system("%s -A -S%s %s" % (self._path, script, database))

# Don't forget to register at the factory
registerDisassemblerCMD(IdaCMD.identify, IdaCMD)
