Open source fingerprinting
==========================
Identifier Plugin
-----------------
The ```karta_identifier.py``` script identifies the existence of supported open source projects inside the given binary, and aims to fingerprint the exact version of each located library.
Once your binary was loaded to IDA, simply load the script ```karta_identifier.py```, and it will output the results to the output window and to an output file.
Here is an example output after running the script on an HP OfficeJet firmware:

```
Karta Identifier - printer_firmware.bin:
========================================

Identified Open Sources:
------------------------
libpng: 1.2.29
zlib: 1.2.3
OpenSSL: 1.0.1j
gSOAP: 2.7
mDNSResponder: unknown

Identified Closed Sources:
--------------------------
Treck: unknown

Missing Open Sources:
---------------------
OpenSSH: Was not found
net-snmp: Was not found
libxml2: Was not found
libtiff: Was not found
MAC-Telnet: Was not found

Final Note - Karta
------------------
If you encountered any bug, or wanted to add a new extension / feature, don't hesitate to contact us on GitHub:
https://github.com/CheckPointSW/Karta
```

As can be seen, the output includes 3 parts:
1.  List of identified open source libraries, with their version if identified or "unknown" if failed to identify it
1.  List of identified closed source libraries
1.  List of missing open source libraries, so that you will know what libraries are supported by the identifier at the moment

Manual Identification
---------------------
Sometimes we would like to feed **Karta** with some knowledge we already acquired about the matched open source. When **Karta** locates a library, but fails to identify it's exact version, we can manually tell it the version so the matcher could match it. For example, in the above example we could manually configure the version for the "mDNSResponder" library which we located, but failed to identify.

User defined library versions can be declared by running the ```karta_manual_identifier.py``` in the command line, using the following arguments:
```
C:\Users\user\Documents\Karta\src>python karta_manual_identifier.py --help
usage: karta_manual_identifier.py [-h] [-D] bin

Enables the user to manually identify the versions of located but unknown
libraries, later to be used by Karta's Matcher.

positional arguments:
  bin          path to the disassembler's database for the wanted binary

optional arguments:
  -h, --help   show this help message and exit
  -D, --debug  set logging level to logging.DEBUG
```
The script will store the configurations in a ```*_knowledge.json``` file near the disassembler's database file.

**Note:** After we manually identify the version of a previously located but unknown library, future calls to the identifier plugin will use our supplied version automatically.