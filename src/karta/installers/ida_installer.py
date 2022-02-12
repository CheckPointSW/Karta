import os
import re
from shutil import copyfile

from .common_installer import detect_installation, set_default_disassembler


disassembler_name = "ida_path"

def detect_ida(save_file):
    """
    find where ida is installed by this regex, should work for both windows and linux
    """
    pattern = re.compile("ida( pro )?-?\d\.\d", re.IGNORECASE)
    return detect_installation(pattern, save_file)

def main():
    """
    detect ida copy library files into its plugins directory and add the plugin to be run on start
    """
    path = detect_ida(disassembler_name)
    set_default_disassembler(disassembler_name)
    src_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
    ida_plugin = os.path.join(src_dir, "plugins", "ida_plugin.py")
    plugin_dst = os.path.join(path, "plugins", "ida_karta.py")
    copyfile(
        ida_plugin,
        plugin_dst
    )



if __name__ == "__main__":
    main()
