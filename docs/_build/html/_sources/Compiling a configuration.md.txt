Compiling a configuration file
==============================
Compiling the Open Source
-------------------------
Adding support for a new version for an already supported library, requires only to compile a new (*.json) configuration file for it.
As Karta is a source code assisted plugin, this process requires you to compile the open source library according to the guidelines of the open source project, together with the specific guidelines that can be found in the ```compilations``` directory.

**Important:** Karta will need two compiled parts for building the configuration
1.  A static library - .a in Linux, and .lib in Windows
1.  A folder containing all of the *.o (in Linux) or *.obj (in Windows) files

**Note:** Some libraries, such as OpenSSL, are split to several static libraries. In this case you should make sure you found all of the parts for each such static library

Running the script
------------------
Now that we have all of the parts, we should run **karta_analyze_src.py** in the command line, using the following arguments:

```
C:\Users\user\Documents\Karta\src>python karta_analyze_src.py
Wrong amount of arguments, got 0, expected 4
Usage: karta_analyze_src.py <library name> <library version> <bin dir (with *.o or *.obj files)> <compiled archive: *.a or *.lib>
Exiting
```

1.  Name of the open source library (case sensitive)
1.  Version of the library (as will be identified by the identifier script)
1.  Path to the directory that contains the compiled (*.o / *.obj) files
1.  Path to the compiled static library file
In case there are multiple static libraries, chain more arguments and maintain the current order: <bin dir> <static library path>

The script will ask you for the path to your disassembler (IDA), and will suggest a default path. Enter the path to your disassembler, press ENTER, and a progress bar will show you the progress of the script.

Storing the config file
-----------------------
In the end, a new *.json file will be generated (using the library name + version), and it should be stored together with the rest of the configuration files in the ```configs``` directory.