#
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Double Jumps


from utils import mipsrop

mips_rop = mipsrop.MipsRop(currentProgram)
doubles = mips_rop.find_doubles()

doubles.pretty_print()
