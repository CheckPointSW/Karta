def getArchiveFiles(ar_path):
    """Return an ordered list of the files within the .ar archive.

    Args:
        ar_path (str): path to the compiled *.ar file

    Return Value:
        Ordered list of file names
    """
    ar_fd = open(ar_path, 'rb')
    is_windows = ar_path.endswith(".lib")

    # check the signature
    if ar_fd.read(8) != b'!<arch>\n':
        raise ValueError("Invalid archive signature")

    # split the content to parts
    ar_content = ar_fd.read()
    names = []
    for ar_part in ar_content.split('\x60\x0A')[:-1]:
        # .ar file format (unix) seems simpler
        if not is_windows:
            # sanity check
            if len(ar_part) < 58:
                continue
            # now read the metadata of the record
            name = ar_part[-58:].split('/')[0]
        # .lib file format is more complex
        else:
            if ar_part.find(".obj") == -1:
                continue
            name = ar_part.split(".obj")[-2].split('\x00')[-1].split('\\')[-1] + ".obj"
            name = name.strip()
        # append the new record
        if name not in names:
            names.append(name)
    ar_fd.close()
    return names
