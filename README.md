Converting IDA Plugins from [devttyS0](https://github.com/devttys0/ida) to 
Ghidra framework. To install, clone and add the script directory via Ghidra's 
Script Manager. If you check the 'In Tool' checkbox they will appear under a 
'TNS' tag. 

# Call Chain
Display the call chain, if it exists between two functions. The output will 
be display using an modified graphviz library as well as Ghidra's console.

![Call Chain Graph](./img/call_chain_graph.png)

![Call Chain Text](./img/call_chain_text.png)

# Fluorescence
Highlight or un-highlight all function calls in the current binary.

![Highlighted function calls](./img/fluorescence.png)

# Function Profiler
Display all cross references from the current function. Will display all 
strings, functions, and labels. Depending on the size of the function, the 
console output size may need to be adjusted to view all the text.

![Function Profiler Output](./img/function_profiler.png)

# Local Cross References
Find references to the selected item in the current function.

![Local Cross References](./img/local_xrefs.png)

# Rename Variables
Rename saved stack variables for easier tracking. Only valid in MIPS.

![Rename stack variables](./img/rename_variables.png)

# MIPS ROP Gadget Finder (Work in Progress)
Find ROP gadgets in MIPS disassembly. Currently in development, these are the 
"working" pieces so far. Sorry if functionality changes greatly.
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

## Stack Finder
Find gadgets that place a stack address in a register.

![Stack Finders](./img/stack_finder.png)

## System Gadgets
Find gadgets suitable for calling system with user controlled arguments.

![System Gadgets](./img/system_gadget.png)


# Coming Soon
In order, probably, of implementation. They may not be written if I get to them
and they don't make sense to implement.

* mipsrop (In development)
* codatify
* rizzo
* leafblower
