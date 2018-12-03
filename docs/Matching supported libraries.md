Matching supported libraries
============================
Step #0
-------
It is always recommended to start with the identifier script, so you would know if you already have pre-compiled configurations for all the libraries you need.
In case it is needed, a guide for compiling a new configuration can be found in the next section.

Matcher Plugin - Start
----------------------
Assuming you are all set and ready to go, and that your binary is already open in IDA, load the **karta_matcher.py** script and set up the needed configurations:
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
