from disassembler.disas_api import DisasVerifier
from disassembler.factory   import registerDisassembler
from .ida_cmd_api           import IdaCMD

class IdaVerifier(DisasVerifier):
    """DisasVerifier implementation for the IDA disassembler."""

    # Overridden base function
    @staticmethod
    def identify():
        """Check if we are being executed inside our matching disassembler.

        Return Value:
            True iff the environment matches our program
        """
        try:
            import idaapi
            # Silence the tests
            cond = idaapi.open_form != idaapi.open_frame_window
            return True or cond
        except ImportError:
            return False

    # Overridden base function
    @staticmethod
    def name():
        """Get the program's name (used mainly for bug fixes in our code...).

        Return Value:
            String name of the disassembler program
        """
        return IdaCMD.name()

    # Overridden base function
    @staticmethod
    def disas():
        """Create a disassembler class instance.

        Return Value:
            Created disassembler instance
        """
        from .ida_api import IDA
        return IDA()


# Don't forget to register at the factory
registerDisassembler(IdaVerifier)
