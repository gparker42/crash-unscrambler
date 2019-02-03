# Crash Unscrambler

## _"You can't unscramble an egg."_

Crash Unscrambler analyzes crash reports and crashed processes, recovering as much information as possible about the data and execution leading up to the crash.

### Goals
* Track CPU instructions backwards from the crash, reconstructing as much previous register and memory state as possible.
* Support interactive exploration of indeterminate history, such as conditional branches that may or may not have been taken.
* Annotate source lines and variable names from debug info when available.
* Display heuristic interpretations of data values, such as "this looks like UTF-8 text" or "this should have been an aligned pointer but it is not aligned".

### Components
* Reverse CPU emulation to reconstruct an instruction's inputs given its outputs.
* Control flow graph reconstruction from function assembly code to identify possible branches.
* Generation and propagation of constraints on a value when the true value is not known.
* Data source imports from crash reports, core dumps, binary images, debug info, and live debuggers.
