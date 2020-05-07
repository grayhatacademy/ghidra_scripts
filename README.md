Ghidra scripts to support IOT exploitation. Some of the scripts are a port 
of [devttyS0](https://github.com/devttys0/ida) IDA plugins and others are 
new scripts that I found a need for. To install, clone and add the script 
directory via Ghidra's Script Manager. If you check the 'In Tool' checkbox they 
will appear under a 'TNS' tag. 

## Scripts
Below is a simple overview of the available scripts. If the scripts are broken up into multiple parts then bullets are given with high level overviews. Click on the link for each to see a more in-depth explanation with screenshots. 

# [ARM ROP Finder](readmes/armrop.md) 
Script to find and support finding ARM ROP gadgets. 

- Gadgets
    - Find double jumps.
    - Move small value to r0.
    - Get control of more or different registers.
    - Move values between registers.
    - Find strings or shellcode on the stack.
    - Find custom gadgets based on regular expressions.
    - Gadgets to call system with a string argument in r0.

- Support
    - Convert entire program to Thumb instructions. 
    - List summary of saved gadgets.

# [Call Chain](readmes/callchain.md)
Find call chains between two user specified functions. Results are displayed in a png.

# [Codatify](readmes/codatify.md) 
- Fixup code - defines all undefined data in the .text section as code and creates a function if it can.
- Fixup data - define uninitialized strings and pointers. Searches for function tables and renames functions based on their discovery. 

# [Fluorescence](readmes/fluorescence.md)
Highlight function calls.

# [Function Profiler](readmes/func_profiler.md)
Display cross refs from the current function.

# [Leaf Blower](readmes/leafblower.md)
- Format Strings - Find functions that accept format strings as parameters.
- Leaf Functions - Identify potential leaf functions such as strcpy, strlen, etc.

# [Local Cross References](readmes/local_cross_ref.md)
Find references to items in the current function.

# [MIPS ROP Finder](readmes/mips_rop.md)
Scripts to find and support finding MIPS ROP gadgets.

- Gadgets
    - Double Jumps
    - Epilogue
    - Find custom gadgets
    - Indirect Return
    - li a0
    - Prologue
    - System Gadgets

- Chain Builder
    - Build ROP chain to call shellcode
    - Build ROP chain to call system with controllable string. 

- Support
    - Summary

# [Operator](readmes/operator.md)
Display all calls to a function and identify the source of the parameters it is called with taking variadic arguments into account if they are present.

# [Rename Variables](readmes/rename_variables.md)
Rename saved stack variables. (MIPS only)

# [Rizzo](readmes/rizzo.md)
Create fuzzy function signatures that can be applied to other projects.

