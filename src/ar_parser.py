import unix_ar

def getArchiveFiles(ar_path) :
    """Returns an orderred list of the files within the .ar archive
    
    Args:
        ar_path (str): path to the compiled *.ar file

    Return Value:
        Orderred list of file names
    """
    ar = unix_ar.open(ar_path, 'r')
    names = filter(lambda e : len(e) > 0, map(lambda e : e._name[:-1], ar.infolist()))
    ar.close()
    return names
