# Find MIPS ROP gadgets that load a small value into a0. Useful for calling sleep.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Gadgets.Li a0


from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

li_a0 = mipsrop.MipsInstruction('.*li', 'a0', '0x.*')

mips_rop = mipsrop.MipsRop(currentProgram)
sleep_calls = mips_rop.find_instructions([li_a0])

sleep_calls.pretty_print()
