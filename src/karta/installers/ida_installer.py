import os
import re
from shutil import copytree, copyfile

from .common_installer import detect_installation, set_default_disassembler


disassembler_name = "ida_path"

def detect_ida(save_file):
    """
    find where ida is installed by this regex, should work for both windows and linux
    """
    pattern = re.compile("ida( pro )?-?\d\.\d", re.IGNORECASE)
    return detect_installation(pattern, save_file)

def wanted_ida_files(adir, filenames):
    """
    list all files that will go into the ida plugins directory
    no need to copy neither compiled python files nor files not relevent for ida
    """
    filelist = list()
    caches = re.compile("(__pycache__|.*\.pyc)")
    non_needed_content = re.compile("(installers|plugins|.*_path)")
    ida_valid = re.compile("(IDA|.*\.py)")
    for filename in filenames:
        if type(adir) != str and adir.name == "disassembler" and not ida_valid.match(filename):
            filelist.append(filename)
            continue
        if caches.match(filename) or non_needed_content.match(filename):
            filelist.append(filename)
    return filelist

def main():
    """
    detect ida copy library files into its plugins directory and add the plugin to be run on start
    """
    path = detect_ida(disassembler_name)
    set_default_disassembler(disassembler_name)
    src_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
    ida_plugin = os.path.join(src_dir, "plugins", "ida_plugin.py")
    plugin_dir = os.path.join(path, "plugins")
    karta_dir = os.path.join(plugin_dir, "karta")
    plugin_dst = os.path.join(plugin_dir, "ida_karta.py")
    copytree(
        src_dir,
        karta_dir,
        ignore=wanted_ida_files,
        dirs_exist_ok=True
    )
    copyfile(
        ida_plugin,
        plugin_dst
    )



if __name__ == "__main__":
    main()
