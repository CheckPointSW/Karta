import os
import platform

from ..config.utils import addDisassembler, getDisassembler, setDefaultDisassembler


def common_locations():
    """
        Gets a list of common places where a disassembler may be installed
    """
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


def detect_installation(pattern, installation_file):
    """
        If already installed get the installation path
        Detect installation of a disassembler by a regex provided by its specific installer
        Save it into a file so you may use it as a default
        If its not in any of the common locations ask the user to enter it
    """
    disassembler = getDisassembler(installation_file)
    if disassembler is not None:
        return disassembler

    for location in common_locations():
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


def set_default_disassembler(disassembler_name):
    setDefaultDisassembler(disassembler_name)
