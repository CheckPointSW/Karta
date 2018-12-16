Matching supported libraries
============================
Prerequisites
-----------------
**Identifier**

It is always recommended to start with the identifier script, so you would know if you already have pre-compiled configurations for all the libraries you need.
In case it is needed, a guide for compiling a new configuration can be found in the next section.

**Function Analysis**

**Karta** is highly sensitive to the quality of the function analysis that was done by IDA. It is important to make sure that the matcher plugin is invoked only *after* the binary is well analyzed. For example: even if there is an un-reffed code snippet, make sure that IDA marked it as a function if it is an un-reffed function.

Manual Anchors
--------------
Sometimes we would like to feed **Karta** with some knowledge we already acquired about the matched open source. In this case we can define "manual anchors", and **Karta** will use them as part of the initial anchors list.
User defined anchors can be declared by running the ```karta_manual_anchor.py``` in the command line, using the following arguments:
```
C:\Users\user\Documents\Karta\src>python karta_manual_anchor.py --help
usage: karta_manual_anchor.py [-h] [-D] [-W] bin lib-name lib-version configs

Enables the user to manually defined matches, acting as manual anchors, later
to be used by Karta's Matcher.

positional arguments:
  bin            path to the disassembler's database for the wanted binary
  lib-name       name (case sensitive) of the relevant open source library
  lib-version    version string (case sensitive) as used by the identifier
  configs        path to the *.json "configs" directory

optional arguments:
  -h, --help     show this help message and exit
  -D, --debug    set logging level to logging.DEBUG
  -W, --windows  signals that the binary was compiled for Windows
```

The script will store the configurations in a ```*_knowledge.json``` file near the disassembler's database file.

Matcher Plugin - Start
----------------------
Assuming you are all set and ready to go, and that your binary is already open in IDA, load the ```karta_matcher.py``` script and set up the needed configurations:
*  Full path for Karta's configuration directory - the ```configs``` dir with all of the *.json files
*  In case of a binary that was compiled for Windows, set up the checkbox (not required for firmware binaries)
Once again, the output will be shown in IDA's output window, and will also be stored to a file.

Every matched open source library will open 2 windows:
1.  Window with the match results from the library
1.  Window with the proposed match results for external (usually libc) functions, used by the open source library

Matcher Plugin - Output
-----------------------
The matched library functions include the reason for the matching.
As some matching rules are much more accurate than others, they are colored in dark-green, while the others are marked in green.
You can now select a subset of matches, right click, and export the selected matches to be names in IDA. Or, you can simply right click and import all of the matches directly to IDA.

The matching process is relatively fast (less than a minute for a small-medium open source), however no user interaction is needed after each library is matched, so you can also run it at night and check all of the results in the morning.
