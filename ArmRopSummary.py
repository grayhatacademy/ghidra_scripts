# Print a summary of ROP gadgets that are bookmarked with ropX.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Summary


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

arm_rop = armrop.ArmRop(currentProgram)
arm_rop.summary()
