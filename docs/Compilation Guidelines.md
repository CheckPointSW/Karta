Compilation Guidelines
======================

Basic Invariant
---------------
Karta's main compilation assumption is that the source compilation can't modify (inline / split to parts) a function if the wanted binary hadn't done the exact modification to this function.
This means that:
1.  A function can be modified (inlined) in the binary even if we didn't inline it in our "source" compilation
1.  If a function was modified in our "source" compilation, it must be modified in the same way in our wanted binary

Since we want to maintain this basic invariant, we usually want to compile our open source library with flag for:
*  No inlining
*  No compiler optimizations

Windows Compilation
-------------------
It seems that when compiling a binary using ```nmake``` or ```visual studio```, the Window's compilation adds some linker optimizations. As we couldn't imitate these linker optimizations when compiling with ```gcc```, Karta can (and should) support 2 different configurations for the same version of a specific library:
1.  Basic (unix) configuration - Used for Linux, Mac, of various firmwares
1.  Windows configuration
Karta can automatically identify the type of the configuration file it was requested to create, based on the suffix of the static library file:
*  .lib - Windows static library => Windows configuration
*  .a - Linux static library => Basic configuration

Bitness - 32 vs 64
------------------
After various testing rounds, it seems that a configuration for 32 bits can also achieve great matching results for 64 bit binaries. Therefor there is no need to maintain two different configurations files, one for each bitness mode.
When compiling a configuration file, the rule of thumb should be:
*  Basic (unix) based configurations should be compiled for 32 bits (-m32) - firmware binaries are usually 32 bits
*  Windows configurations should be compiled for 64 bits

Updating the compilation notes
------------------------------
After a successful compilation was made, a new "compilation tips" file should be created and stored under the ```compilations``` folder. The file's name should be ```<library name>.txt``` and it should have a similar structure as the already existing files.

Adding a python identifier for your library
-------------------------------------------
As most of the open source projects have unique string identifiers that hold their exact version, all of the currently supported fingerprinting plugins are based on a basic string search.

**searchLib():** Scans all of the strings in the binary (using the ```self._all_strings``` singleton), in search for a key string (holding the version) or a unique library string that is stored locally near a clear version string.

**identifyVersions():** Will be called only after ```searchLib``` had identified the existence of the library in the binary. This function is responsible for parsing the exact library version, usually using the ```self._version_string``` that was found by ```searchLib```.