# Find ARM ROP gadgets that put a stack address in a register. Useful for calling functions with a user controlled string.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Stack Finder


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

sf_saved_reg = armrop.ArmInstruction('add', '^(r[01]?\d)', 'sp')

arm_rop = armrop.ArmRop(currentProgram)
stack_finders = arm_rop.find_instructions([sf_saved_reg])

stack_finders.pretty_print()
