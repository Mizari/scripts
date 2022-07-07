# scripts
Various scripts for IDA Pro

**const_adder.py**  
Will try to find C strings in .data Segments and make them constant for better representation in HexRays window

**demangler.py**  
Script for mass demangling function names. Allows for better control of what to skip.

**detect_offsets.py**  
Will try to find integers in .data segment, that point to valid memory, and then make them pointers. It helps with analysis

**fastclear.py**  
Script, that adds action (Ctrl-X instead of default Quit) for output window clearing. Works everywhere.

**recolour_calls.py**  
Darkmode-friendly script that colorizes calls instructions in assembly view.

**remove_spaces_from_structs**  
Removes spaces from structures and local types. Useful for templated C++ types for IDA, which works pretty badly with spaces in types.