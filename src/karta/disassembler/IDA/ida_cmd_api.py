import os
import asyncio

from ..disas_api import DisasCMD
from ..factory   import registerDisassemblerCMD


class IdaCMD(DisasCMD):
    """DisasCMD implementation for the IDA disassembler."""

    # Overridden base function
    @staticmethod
    def identify(path):
        """Check if the given command-line path refers to this disassembler.

        Args:
            path (str): command-line path to some disassembler (maybe for us)

        Return Value:
            True iff the command-line path refers to our program
        """
        return os.path.split(path)[-1].split(".")[0].lower().startswith("ida")

    # Overridden base function
    @staticmethod
    def name():
        """Return the program's name (used mainly for bug fixes in our code...).

        Return Value:
            String name of the disassembler program
        """
        return "IDA"

    # Overridden base function
    async def createDatabase(self, binary_file, is_windows):
        """Create a database file for the given binary file, compiled to windows or linux as specified.

        Args:
            binary_file (path): path to the input binary (*.o / *.obj) file
            is_windows (bool): True if this is a binary that was compiled for windows (*.obj), False otherwise (*.o)

        Return Value:
            path to the created database file
        """
        type = "elf" if not is_windows else "coff"

        if not hasattr(self, "is64"):
            self.decideArchitecureChoices(binary_file, is_windows)

        database_file = binary_file + self.suffix
        # execute the program
        process = await asyncio.create_subprocess_exec(self._path, "-A" , "-B", f"-T{type}" ,f"-o{database_file}", binary_file)
        await process.wait()
        # return back the (should be) created database file path
        return database_file

    # Overridden base function
    async def executeScript(self, database, script):
        """Execute the given script over the given database file that was created earlier.

        Args:
            database (path): path to a database file created by the same program
            script (path): python script to be executed once the database is loaded
        """
        process = await asyncio.create_subprocess_exec(self._path, "-A", f"-S{script}", database)
        await process.wait()
    
    def isSupported(self, feature_name):
        return hasattr(self, feature_name)

    async def createAndExecute(self, binary_file, is_windows, script):
        type = "elf" if not is_windows else "coff"

        if not hasattr(self, "is64"):
            self.decideArchitecureChoices(binary_file, is_windows)

        # execute the program
        process = await asyncio.create_subprocess_exec(self._path, "-A", "-c" , f"-S{script}", f"-T{type}", binary_file)
        await process.wait()

    def decideArchitecureChoices(self, binary_file, is_windows):
        # machine type header of pe
        # specified in that order, amd64, arm64, ia64, loongarch64, riscv64
        ARCH64PE = [b"\x64\x86", b"\x64\xaa", b"\x00\x02", b"\x64\x62", b"\x64\x50"]

        # machine type header of elf
        ARCH64ELF64 = b"\x02"

        # because we get the path to the folder of the dissasembler
        # we need to define whether it is a 64 or 32 bit one
        # so we check the respective fields in coff files and elf files
        # and define the file ending and the ida to use based on tehm
        self._path = os.path.join(self._path,  "ida")
        self.is64 = False
        with open(binary_file, 'rb') as f:
            if is_windows:
                # read machine type header and check whether it is in a list
                # of 64 bit architectures
                machine_type = f.read(2)
                if machine_type in ARCH64PE:
                    self.is64 = True
            else:
                # read the 32bit / 64bit field
                machine = f.read(5)[4:]
                if machine == ARCH64ELF64:
                    self.is64 = True
        self.suffix = ".i64" if self.is64 else ".idb"
        self._path += "64" if self.is64 else ""
        
# Don't forget to register at the factory
registerDisassemblerCMD(IdaCMD.identify, IdaCMD)
