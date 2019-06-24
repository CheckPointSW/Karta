Thumbs Up
=========
Introduction
------------
**Karta** is highly sensitive to the quality of the function analysis that was done by IDA. Therefore, we developed **Thumbs  Up**. This mini-plugin should be used as a pre-process phase to automatically achieve to main goals:
1. Drastic improvement of the disassembler's analysis
2. For ARM binaries - clear seperation between ARM and THUMB code regions

More information about the script and it's Machine-Learning-based analysis, can be found in this detailed blog post: https://research.checkpoint.com/thumbs-up-using-machine-learning-to-improve-idas-analysis.

**Important Note**
Thumbs Up performs a series of major changes to the binary on which it was invoked. We highly recommend that you **backup** your original binary **before** executing the script. Better safe than sorry.

Firmware Files
--------------
Although the plugin was mainly designed for improving the analysis of firmware files, there are still some precondition steps that are required before executing the script.
1. Make sure that the different code segments are clearly defined in IDA
2. **Code** segments (executable and not writable) will be treated differently than **Data** segments (non executable)

The list of code segments and data segments will be outputed to the screen (and log) at the start of the script.
Once the segments are properly configured, simply load the script file named ```thumbs_up/thumbs_up_firmware.py``` and wait for the magic to happen.

The script's performance heavily depends on IDA's analysis, as well as on the different phases it has to perform. On ARM binaries you should expect a much longer execution time than on other binaries, as it also needs to adjust the ARM/THUMB code transitions.

ELF Files
---------
Executing the script on ELF files is easier, as the ELF header already defines all the information we need for the code segments. For ELF binaries one should load the script file named ```thumbs_up/thumbs_up_ELF.py``` and wait for the magic to happen.