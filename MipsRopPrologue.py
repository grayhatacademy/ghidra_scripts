# Find MIPS ROP gadgets near the beginning of functions that allow for stack pointer movement.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Gadgets.Prologue


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

prologue = mipsrop.MipsInstruction('.*addiu', 'sp', 'sp', '-.*')

mips_rop = mipsrop.MipsRop(currentProgram)
function_prologue = mips_rop.find_instructions([prologue])

function_prologue.pretty_print()
