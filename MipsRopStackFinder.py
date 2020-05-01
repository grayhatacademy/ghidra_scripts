# Find MIPS ROP gadgets that put a stack address in a register.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Gadgets.Stack Finder


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

sf_saved_reg = mipsrop.MipsInstruction('.*addiu', '[sva][012345678]', 'sp')

mips_rop = mipsrop.MipsRop(currentProgram)
stack_finders = mips_rop.find_instructions([sf_saved_reg])

stack_finders.pretty_print()
