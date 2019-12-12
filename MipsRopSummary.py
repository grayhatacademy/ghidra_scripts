# Print a summary of ROP gadgets that are bookmarked with ropX.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Summary


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

mips_rop = mipsrop.MipsRop(currentProgram)
mips_rop.summary()
