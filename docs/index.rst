.. Karta documentation master file, created by
   sphinx-quickstart on Mon Dec 03 12:12:35 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.
   
.. toctree::
   :maxdepth: 2
   :caption: User Guide:
   :hidden:

   Installation
   Thumbs Up
   Open Source Fingerprinting
   Matching supported libraries
   
.. toctree::
   :maxdepth: 2
   :caption: Supporting new versions:
   :hidden:

   Compiling a configuration
   Compilation Guidelines
   Supporting a new library
   
.. toctree::
   :maxdepth: 2
   :caption: Matching Guidelines:
   :hidden:

   matching_basics
   scoring_tips
   
.. toctree::
   :maxdepth: 2
   :caption: Modularity:
   :hidden:

   disassembler
   file_layer
   
..
   
::

	/$$   /$$                       /$$              
	| $$  /$$/                      | $$              
	| $$ /$$/   /$$$$$$   /$$$$$$  /$$$$$$    /$$$$$$ 
	| $$$$$/   |____  $$ /$$__  $$|_  $$_/   |____  $$
	| $$  $$    /$$$$$$$| $$  \__/  | $$      /$$$$$$$
	| $$\  $$  /$$__  $$| $$        | $$ /$$ /$$__  $$
	| $$ \  $$|  $$$$$$$| $$        |  $$$$/|  $$$$$$$
	|__/  \__/ \_______/|__/         \___/   \_______/

Brief
=====
"Karta" (Russian for "Map") is an IDA Python plugin that identifies and matches open-sourced libraries in a given binary. The plugin uses a unique technique that enables it to support huge binaries (>200,000 functions), with almost no impact over the overall performance.

The matching algorithm is location-driven. This means that it's main focus is to locate
the different compiled files, and match each of the file's functions based on their original order within the file. This way, the matching depends on K (number of functions in the open source) instead of N (size of the binary), gaining a significant performance boost as usually N >> K.

We believe that there are 3 main use cases for this IDA plugin:

1. Identifying a list of used open sources (and their versions) when searching for a useful 1-Day
2. Matching the symbols of supported open sources to help reverse engineer a malware
3. Matching the symbols of supported open sources to help reverse engineer a binary / firmware when searching for 0-Days in proprietary code

Identifier
----------
Karta's identifier is a smaller plugin that identifies the existence, and fingerprints the versions, of the existing (supported) open source libraries within the binary. No more need to reverse engineer the same open-source library again-and-again, simply run the identifier plugin and get a detailed list of the used open sources.
Karta currently supports more than 10 open source libraries, including:

* OpenSSL
* Libpng
* Libjpeg
* NetSNMP
* zlib
* etc.

Matcher
-------
After identifying the used open sources, one can compile a ``.json`` configuration file for a specific library (libpng version 1.2.9 for instance). Once compiled, Karta will automatically attempt to match the functions (symbols) of the open source in the loaded binary. In addition, in case your open source used external functions (memcpy, fread, or zlib_inflate), Karta will also attempt to match those external functions as well. 

Credits
-------
This project was developed by me (see contact details below) with help and support from my research group at Check Point (Check Point Research).

Links
-----
* https://github.com/CheckPointSW/Karta
* https://research.checkpoint.com/karta-matching-open-sources-in-binaries/
* https://research.checkpoint.com/thumbs-up-using-machine-learning-to-improve-idas-analysis

Contact
-------
* `@EyalItkin <https://twitter.com/EyalItkin>`_ 
* eyalit at checkpoint dot com