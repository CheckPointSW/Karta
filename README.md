[![Build Status](https://travis-ci.com/CheckPointSW/Karta.svg?branch=master)](https://travis-ci.org/CheckPointSW/karta) [![Docs Status](https://readthedocs.org/projects/karta/badge/?version=latest)](https://readthedocs.org/projects/karta)

```
 /$$   /$$                       /$$              
| $$  /$$/                      | $$              
| $$ /$$/   /$$$$$$   /$$$$$$  /$$$$$$    /$$$$$$ 
| $$$$$/   |____  $$ /$$__  $$|_  $$_/   |____  $$
| $$  $$    /$$$$$$$| $$  \__/  | $$      /$$$$$$$
| $$\  $$  /$$__  $$| $$        | $$ /$$ /$$__  $$
| $$ \  $$|  $$$$$$$| $$        |  $$$$/|  $$$$$$$
|__/  \__/ \_______/|__/         \___/   \_______/
``` 

## Purpose
"Karta" (Russian for "Map") is an IDA Python plugin that identifies and matches open-sourced libraries in a given binary. The plugin uses a unique technique that enables it to support huge binaries (>200,000 functions), with almost no impact on the overall performance.

The matching algorithm is location-driven. This means that it's main focus is to locate
the different compiled files, and match each of the file's functions based on their original order within the file. This way, the matching depends on K (number of functions in the open source) instead of N (size of the binary), gaining a significant performance boost as usually N >> K.

We believe that there are 3 main use cases for this IDA plugin:
1. Identifying a list of used open sources (and their versions) when searching for a useful 1-Day
2. Matching the symbols of supported open sources to help reverse engineer a malware
3. Matching the symbols of supported open sources to help reverse engineer a binary / firmware when searching for 0-Days in proprietary code

## Read The Docs
https://karta.readthedocs.io/

## Installation (Python 3 & IDA >= 7.4)
For the latest versions, using Python 3, simply git clone the repository and run the ```setup.py install``` script.
Python 3 is supported since versions v2.0.0 and above.

## Installation (Python 2 & IDA < 7.4)
As of the release of IDA 7.4, Karta is only actively developed for IDA 7.4 or newer, and Python 3.
Python 2 and older IDA versions are still supported using the release version v1.2.0, which is most probably going to be the last supported version due to python 2.X end of life.

## Identifier
Karta's identifier is a smaller plugin that identifies the existence, and fingerprints the versions, of the existing (supported) open source libraries within the binary. No more need to reverse engineer the same open-source library again-and-again, simply run the identifier plugin and get a detailed list of the used open sources.
Karta currently supports more than 10 open source libraries, including:
* OpenSSL
* Libpng
* Libjpeg
* NetSNMP
* zlib
* Etc.

## Matcher
After identifying the used open sources, one can compile a .JSON configuration file for a specific library (libpng version 1.2.29 for instance). Once compiled, Karta will automatically attempt to match the functions (symbols) of the open source in the loaded binary. In addition, in case your open source used external functions (memcpy, fread, or zlib_inflate), Karta will also attempt to match those external functions as well. 

## Folder Structure
* **src:** source directory for the plugin
* **configs:** pre-supplied *.JSON configuration files (hoping the community will contribute more)
* **compilations:** compilation tips for generating the configuration files, and lessons from past open sources
* **docs:** sphinx documentation directory

### Additional Reading
* https://research.checkpoint.com/karta-matching-open-sources-in-binaries/
* https://research.checkpoint.com/thumbs-up-using-machine-learning-to-improve-idas-analysis

### Credits
This project was developed by me (see contact details below) with help and support from my research group at Check Point (Check Point Research).

### Contact (Updated)
This repository was developed and maintained by me, Eyal Itkin, during my years at Check Point Research. Sadly, with my departure of the research group, I will no longer be able to maintain this repository. This is mainly because of the long list of requirements for running all of the regression tests, and the IDA Pro versions that are involved in the process.

Please accept my sincere apology.
[@EyalItkin](https://twitter.com/EyalItkin)