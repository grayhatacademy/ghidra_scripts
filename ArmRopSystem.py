# Find ARM ROP gadgets for calling system with a user controlled argument.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.System Calls


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

set_a0 = armrop.ArmInstruction('add', 'r0', 'sp')

arm_rop = armrop.ArmRop(currentProgram)
system_rops = arm_rop.find_instructions([set_a0], 'a0')

system_rops.pretty_print()
