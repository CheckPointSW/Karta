import os
import platform

from ..config.utils import addDisassembler, getDisassembler, setDefaultDisassembler


def commonLocations():
    """Get a list of common places where a disassembler may be installed on any os."""
    location_list = list()
    # based on the operating system installation location may vary
    system_lower = platform.system().lower()
    if system_lower == "windows".lower():
        # add drives
        from ctypes import windll
        kernel32 = windll.kernel32
        logical_drives = kernel32.GetLogicalDrives()
        current_letter = 'A'
        while logical_drives > 0:
            if logical_drives & 1 == 1:
                location_list.append(current_letter + ':\\')
            logical_drives >>= 1
            current_letter = chr(ord(current_letter) + 1)
        # add program files
        location_list.append(os.environ['ProgramFiles'])
    elif system_lower == "linux".lower():
        location_list.append("~")
        location_list.append("/opt")
    return location_list


def detectInstallation(pattern, installation_file):
    """Detect a disassembler's installation by regex, if not found get it with input.

    Args:
        pattern (re.Pattern): pattern to detect an installation
        installation_file (str): name of the file to save the disassembler name in

    Return Value:
        Directory of the disassembler file
    """
    disassembler = getDisassembler(installation_file)
    if disassembler is not None:
        return disassembler

    for location in commonLocations():
        for directory in next(os.walk(location))[1]:
            if pattern.match(directory):
                install_directory = os.path.join(location, directory)
                addDisassembler(installation_file, install_directory)
                return install_directory
    try:
        disass_path = input("Please enter the path to the folder of the disassembler: ")
        if os.path.isdir(disass_path):
            path = os.path.abspath(disass_path)
            addDisassembler(installation_file, path)
            return path
        else:
            print("The path you entered is not a directory")
    except KeyboardInterrupt:
        exit(0)


def commonSetDefaultDisassembler(disassembler_name):
    """Call config utils setDefaultDisassembler function."""
    setDefaultDisassembler(disassembler_name)
