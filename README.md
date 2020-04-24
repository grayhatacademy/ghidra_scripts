Port of IDA Plugins from [devttyS0](https://github.com/devttys0/ida) to 
Ghidra framework as well as new plugins. To install, clone and add the script 
directory via Ghidra's Script Manager. If you check the 'In Tool' checkbox they 
will appear under a 'TNS' tag. 

# Table Of Contents

## OG Scripts
[Call Chain](#call_chain) - Find call chains between two functions

[Codatify](#codatify) - Fix up code and data.

[Fluorescence](#fluorescence) - Highlight function calls.

[Function Profiler](#func_profiler) - Display cross refs from the current function.

[Leaf Blower](#leafblower) - Identify common POSIX functions.

[Local Cross References](#local_cross_ref) - Find references to items in the current function.

[MIPS Rop Finder](#mips_rop) - Find ROP gadgets in MIPS disassembly.

[Rename Variables](#rename_variables) - Rename saved stack variables.

[Rizzo](#rizzo) - Create fuzzy function signatures that can be applied to other projects.

## New Scripts
[ARM Rop Finder](#arm_rop) - Find ROP gadgets in ARM disassembly.

[MIPS Rop Finder](#mips_rop) Prologue Gadget - Find controllable gadgets at the beginning of functions that provide stack pointer movement.

[MIPS Rop Finder](#mips_rop) Epilogue Gadget - Find gadgets that grant control of more saved registers.

[Operator](#operator) - Identify calls to functions and the parameters that are provided to the function.

<a name=arm_rop></a>

----

# ARM Rop Finder
Find ROP gadgets in ARM disassembly.

## ArmToThumb
Convert all executable disassembly to Thumb instructions to search for ROP gadgets.
The output of ROP gadets will account for Thumb instructions and display the jump 
address as `ADDRESS + 1 = WHERE_YOU_SHOULD_JUMP`. The operation can be undone 
when finished looking for gadgets.

### Before
ARM disassembly before running the Arm to Thumb plugin.

![Disassembly Before](./img/arm_dis.png)

### After
Disassembly after the conversion.

![Disassembly After](./img/thumb_dis.png)

### Thumb Gadget
Thumb gadgets are shown with their actual address, but when jumping to it from 
a ROP gadget you must jump to the address + 1 to switch to Thumb mode.

![Disassembly After](./img/thumb_gadget.png)

## Find
Find controllable gadgets that contain custom ARM instructions. Regular 
expressions are supported. To search for a move to r0 from anything, simply 
search for 
"`mov r0,.*`".

![ARM ROP Find](./img/armrop_find.png)

## Register Control
Find ARM ROP gadgets that give control of registers by popping them off the stack.

![ARM ROP Register Control](./img/armrop_registercontrol.png)

## Register Move
Find ARM ROP gadgets that move values between registers.

![ARM ROP Register Move](./img/armrop_registermove.png)

## Stack Finder
Find ARM ROP gadgets that put a stack address in a register. Useful for finding shell code and strings on the stack.

![ARM ROP Stack Finder](./img/armrop_stackfinder.png)

## Summary
Print a summary of gadgets that have been book marked with the string `ropX` 
where `X` is the gadgets position in the rop chain. Don't mix ARM And Thumb 
gadgets with the summary, it won't work. I will fix this.

![Creating a Book mark](./img/bookmark.png)

![ARM Gadget Summary](./img/armrop_summary.png)

## System
Find ARM ROP gadgets for calling system with a user controlled argument.

![ARM ROP System Gadget](./img/armrop_system.png)


<a name=call_chain></a>

----

# Call Chain
Display the call chain, if it exists, between two functions. The output will 
be display using a modified graphviz library as well as Ghidra's console.

![Call Chain Graph](./img/call_chain_graph.png)

![Call Chain Text](./img/call_chain_text.png)

<a name=codatify></a>

----

# Codatify

## Fixup Code 
Define all undefined data in the .text section as code and covert it to a 
function if applicable.

### Before

![Code Before](./img/before_code.png)

### After

![Code After](./img/after_code.png)

## Fixup Data
Define uninitialized strings and pointers in the code. All other uninitialized
data is converted to a DWORD. Finally, search for function tables and rename
functions based off the discovered tables.

### Before 

**Data Section**

![Data Before](./img/before_data.png)

**Cross Reference**

![Xref Before](./img/before_xref.png)

### After

**Data Section**

![Data After](./img/after_data.png)

**Cross Reference**

![Xref Before](./img/after_xref.png)

<a name=fluorescence></a>

----

# Fluorescence
Highlight or un-highlight all function calls in the current binary.

![Highlighted function calls](./img/fluorescence.png)

<a name=func_profiler></a>

----

# Function Profiler
Display all cross references from the current function. Will display all 
strings, functions, and labels. Depending on the size of the function, the 
console output size may need to be adjusted to view all the text.

![Function Profiler Output](./img/function_profiler.png)

<a name=leafblower></a>

----

# Leaf Blower 
Identify common POSIX functions such as printf, sprintf, memcmp, strcpy, etc

## Identify Leaf Functions
Identify leaf functions such as strcpy, strlen, atoi, etc.

![Leaf Functions Output](./img/leaf.png)


## Identify Format Parameter Functions
Identify funtions that accept format parameters to identify sprintf, printf, fscanf, etc.


![Leaf Functions Output](./img/format.png)

<a name=local_cross_ref></a>

----

# Local Cross References
Find references to the selected item in the current function.

![Local Cross References](./img/local_xrefs.png)


<a name=operator></a>
----

# Operator
Identify calls and the parameters provided to the function when called. The 
script will take into account variadic arguments if they can be identified, 
however, passing argument via the stack will not.

![Function Calls](./img/operator.png)


<a name=mips_rop></a>
----

# MIPS ROP Gadget Finder
Find ROP gadgets in MIPS disassembly. 

## Double Jumps
Search for gadgets that contain double jumps.

![Double Jump](./img/double.png)

## Epilogue
Find gadgets that give control of saved registers.

![User Input](./img/epilogue_input.png)

![Epilogue Result](./img/epilogue.png)

## Find
Find gadgets that contain custom MIPS instructions. Regular expressions are 
supported. To search for a move to a0 from anything, simply search for 
"`move a0,.*`".

![Find Dialog Box](./img/find_dialog.png)

![Find Result](./img/find.png)

## Indirect Return
Find indirect return gadgets. Call t9 and then return to ra.

![Indirect Return](./img/iret.png)

## Li a0
Find gadgets that load a small value into a0. Useful for calling sleep.

![Li a0](./img/lia0.png)

## Prologue
Find controllable gadgets at the beginning of functions that provide stack pointer movement.

![Prologue Result](./img/prologue.png)

## Stack Finder
Find gadgets that place a stack address in a register.

![Stack Finders](./img/stack_finder.png)

## Summary
Print a summary of gadgets that have been book marked with the string `ropX` 
where `X` is the gadgets position in the rop chain. Double jumps can be displayed
by appending `_d` to the `ropX` bookmark name: `ropX_d`.

![Creating a Book mark](./img/bookmark.png)

![Summary](./img/summary.png)

## System Gadgets
Find gadgets suitable for calling system with user controlled arguments.

![System Gadgets](./img/system_gadget.png)

<a name=rename_variables></a>

----

# Rename Variables
Rename saved stack variables for easier tracking. Only valid in MIPS.

![Rename stack variables](./img/rename_variables.png)


<a name=rizzo></a>

----

# Rizzo

Create function signatures that can be shared amongst different projects. There
are multiple sets of signatures that are generated:

- Formal: Function matches entirely
- Fuzzy: Functions resemble each other in terms of data/call references.
- String: Functions contain same string references.
- Immediate: Functions match based on large immediate value references.

Formal signatures are applied first, followed by string, immediate, and fuzzy.
If a function is considered a match internal calls are also considered for 
renaming. 

## Apply
Apply Rizzo signatures from another project.

![Apply Rizzo Signatures](./img/rizzo_apply.png)

## Save
Save Rizzo signatures from the current project.

![Save Rizzo Signatures](./img/rizzo_save.png)
