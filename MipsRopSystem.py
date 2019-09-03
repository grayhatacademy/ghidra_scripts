# Find MIPS ROP gadgets for calling system with a user controlled argument.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.System Calls


from utils import mipsrop


mips_rop = mipsrop.MipsRop(currentProgram)
mips_rop.find_controllable_calls()

system_rops = mips_rop.find_system_rops()

system_rops.pretty_print()
