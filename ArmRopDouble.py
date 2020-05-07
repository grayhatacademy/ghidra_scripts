# Find ARM ROP gadgets that perform two controllable jumps.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Double Jumps


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

arm_rop = armrop.ArmRop(currentProgram)
doubles = arm_rop.find_doubles()

doubles.pretty_print()
