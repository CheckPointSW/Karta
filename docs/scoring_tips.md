Scoring Tips
==========
Brief
------
During the work on **Karta** I learned quite a few lessons about the nature of scoring algorithms for binary matching. This section will include a list of the tips I found useful, hoping they could help other researchers / developers as well.

Tips
-----
1. **Anchor** functions can easily generate many matches later on.
2. Finding **anchor** functions should be done without any dependency on  the way we later on match additional functions. **Anchor** functions are too important to be missed by optimizations.
3. The compiler *can* sometimes mess around with the order of the functions inside a single compiled binary file. However, it tends to keep the existing order as-is.
4. Don't give (non-constant) positive scoring to artifacts when there is a reasonable scenario in which low meaningfully different functions receive a "match" score only because of this artifact. For example: number of instructions, frame size, etc.
5. Don't jump to make score-based decisions. Round up all of the possible matching candidates, and only pick the promising ones - those who receive enough score points and are way ahead of their competitors.
6. Functions can be be complicated, store a full call order (path per ref, all paths per call), otherwise the call order will trigger a False Positive (a.k.a. **FP**).
7. Try to adaptively learn the characteristics of the matched binary through the eyes of matched couples. For example: does the compiler maintained function locality (matching neighbours)? what is the ratio between the instructions in the binary and the source?
8. Adaptive scoring changes after every match, we can't assume that a change in score implies we should double check / match our candidates.
9. Give bonus score for "exact matching" feature: all (>1) consts matched, all (>1) strings matched, num calls (>1) matched, ...
10. Small functions contain limited scoring artifacts. Double their score so they would have the chance to reach the scoring threshold.
11. Code blocks score is tightly coupled with instruction score, and their sum should be scored accordingly (they shouldn't be handled separately).
12. We can't assume we know the file order in advance, we will have to deduce it on the flight.
13. Using information from the single compiled files, we can see what functions are exported. Non-exported (static) functions can NOT be referenced by the integrating project (or even other library files when there is no inlining in the binary), and we can rely on this fact when we filter our candidates.
14. Large leftovers can lead to false flagging of an external function as an internal one. This mainly means we are prone to errors when two libraries are adjacent and use one another. It also means that several parts of the same library *must* be handled together (as was done in OpenSSL).
15. Scoring based on calls is good, however if we know that these calls are to the wrong functions (using knowledge from previous matches) we should update our score.
16. On Windows there are linker optimizations, and they really mess-up the call graphs and the assumptions about locality / static functions.
17. Basic support for linker optimizations (by detecting collision groups) can drastically improve the matching results.
 