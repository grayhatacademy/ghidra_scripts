# Find MIPS ROP gadgets that perform two controllable jumps.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Gadgets.Double Jumps


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

mips_rop = mipsrop.MipsRop(currentProgram)
doubles = mips_rop.find_doubles()

doubles.pretty_print()
