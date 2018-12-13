Open source fingerprinting
==========================
Identifier Plugin - Start
-------------------------
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
