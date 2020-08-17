def getArchiveFiles(ar_path):
    """Return an ordered list of the files within the .ar archive.

    Args:
        ar_path (str): path to the compiled *.ar file

    Return Value:
        Ordered list of file names
    """
    ar_fd = open(ar_path, "rb")
    is_windows = ar_path.endswith(".lib")

    # check the signature
    if ar_fd.read(8) != b"!<arch>\n":
        raise ValueError("Invalid archive signature")

    # split the content to parts
    ar_content = ar_fd.read()
    names = []
    for ar_part in ar_content.split(b"\x60\x0A")[:-1]:
        # .ar file format (unix) seems simpler
        if not is_windows:
            # sanity check
            if len(ar_part) < 58:
                continue
            # now read the metadata of the record
            name = ar_part[-58:].split(b'/')[0]
            if not name.endswith(b".o"):
                continue
        # .lib file format is more complex
        else:
            if ar_part.find(b".obj") == -1:
                continue
            name = ar_part.split(b".obj")[-2].split(b"\x00")[-1].split(b"\\")[-1] + b".obj"
            name = name.strip()
        # append the new record
        if name not in names and len(name) > 0:
            names.append(name.decode("utf-8"))
    ar_fd.close()
    return names
