Disassembler
==========
IDA
------
On it's initial version **Karta** was developed as an IDA plugin. However, the disassembler is mainly used for extracting artifacts from functions during the creation of the canonical representation. During this phase, we mainly use [sark](https://github.com/tmr232/Sark).

Supporting Other Disassemblers
---------------------------------------
Since **Karta** was developed to be modular, and because one of our researchers ([Itay](https://twitter.com/megabeets_?lang=en)) mainly uses radare2, we added the ability to support other disassemblers.

The  ```src\disassembler\disas_api.py``` file defines the interface needed by **Karta**, and can be split to 3 main parts (as can be seen inside the folder ```src\disassembler\IDA```):
1. Basic API - finding the name of a function, getting a segment list, etc.
2. Cmd API - functionality for activating the disassembler from the command line.
3. Verifier API - key integration point for the factory to be able to decide inside which disassembler are we being run at the current moment.
4. Analysis API - core logic needed for creating the canonical representation of a function.

While the first 3 parts can be easily implemented as empty adapters without any logic, the 4th part is a bit more complex. We recommend developers to read the code from  ``` src\disassembler\IDA\ida_analysis_api.py``` as an example implementation, when trying to implement the same functionality in the added disassembler.