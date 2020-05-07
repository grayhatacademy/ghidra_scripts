# Find ARM ROP gadgets that load a small value into r0. Useful for calling sleep.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Mov r0


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

move_r0 = armrop.ArmInstruction('mov$', 'r0', '#0x[1-9].*')

arm_rop = armrop.ArmRop(currentProgram)
small_value_to_r0 = arm_rop.find_instructions([move_r0])

small_value_to_r0.pretty_print()
