# Find MIPS ROP gadgets for calling system with a user controlled argument.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.System Calls


from utils import mipsrop


set_a0 = mipsrop.MipsInstruction('.*addiu', 'a0', 'sp')

mips_rop = mipsrop.MipsRop(currentProgram)
mips_rop.find_controllable_calls()

system_rops = mips_rop.find_instructions([set_a0], 'a0')

system_rops.pretty_print()
