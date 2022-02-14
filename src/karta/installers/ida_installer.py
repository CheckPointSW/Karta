import os
import re
from shutil import copyfile

from .common_installer import detectInstallation, commonSetDefaultDisassembler


disassembler_name = "ida_path"

def detectIda(save_file):
    """Find where ida is installed by this regex, should work for both windows and linux.

    Args:
        save_file (str): name of the file which will save the path to the disassembler directory

    Return Value:
        Installation folder for the ida pro disassembler
    """
    pattern = re.compile("ida( pro )?-?\\d\\.\\d", re.IGNORECASE)
    return detectInstallation(pattern, save_file)

def main():
    """Detect ida copy plugin file into its plugins directory."""
    path = detectIda(disassembler_name)
    commonSetDefaultDisassembler(disassembler_name)
    src_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
    ida_plugin = os.path.join(src_dir, "plugins", "ida_plugin.py")
    plugin_dst = os.path.join(path, "plugins", "ida_karta.py")
    copyfile(
        ida_plugin,
        plugin_dst
    )


if __name__ == "__main__":
    main()
