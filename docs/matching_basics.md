Karta
=====
Motivation
----------
The main motivation for developing "Karta" was the needed to identify open sources in large firmware files.
My previous experience with other available tools (at the time) was that they have a memory blowup when dealing with large binaries, meaning that sometimes they will completely crash and give no results :(

If we could work with a subset of functions, that will be polynomial to M (number of functions in the open source) and not in N (number of functions in the binary) we could escape the limitations that arise when M << N. And this was the main idea.

Key Idea - Linker Locality
-------
Matching two functions (src and dest) is usually done after converting them into some "canonical" representation. We aim to narrow our search space, and to convert only a minimal set of binary functions into their canonical representation. And here comes the linker to our rescue:
* The compiler usually compiles each source file (.c / .cpp) into a single binary file (.o or .obj depending on the compiler)
* The linker then attaches them all together into a single blob
* This blob will be inserted to the firmware **as is**

**conclusion #1:** The compiled open source will be contained in a single contiguous blob inside the firmware / executable.

**conclusion #2:** Once we find a single representative of that blob (a.k.a **anchor**), we can speculate about the lower and upper bound of this blob in the binary, according to the number of functions we know that should be in the blob

Matching Steps
-------------------
Using these conclusions, "Karta" matches each open source using the following steps:

0. Fingerprint: Identify the existence of the open source, and the version that is being used
1. Search for **anchor** functions: functions with unique and rare artifacts (strings or consts)
2. Draw basic file boundaries: a map for each located file, and overall scope for the entire open source
3. Use **file hints**: search and match functions that contain a string with their source file name
4. Locate **agents**: functions with file-unique artifacts (minor **anchors**)
5. Regular score-based matching:
   * Scoring similarities
   * Control Flow Graph (CFG) analysis
   * **Note:** give special attention for geographic location

Geographic Location
-------------------------
Compilers tend (when they are nice) to preserve the order of the functions in the compiled binary. For example, if "foo()" was defined after "bar()" in the same source file, the compiled "foo" will usually be found right after the compiled "bar".
This means that our matching and scoring logic will pay special attention to geographic characteristics:
1. Possible matching candidates must reside in the same file as our source function
2. Adaptively boost the score of neighbours (according to seen matching history)
3. Use neighbours to "discover" new matching candidates
4. Static functions shouldn't be referenced by functions from other files / outside of our open source

Modularity
-------------
Using these basic concepts, "Karta" was designed to be modular, to allow other matching libraries to use the basic file mapping logic.