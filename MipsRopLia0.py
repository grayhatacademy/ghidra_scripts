# Find MIPS ROP gadgets that load a small value into a0. Useful for calling sleep.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Li a0


from utils import mipsrop

li_a0 = mipsrop.MipsInstruction('.*li', 'a0', '0x.*')

mips_rop = mipsrop.MipsRop(currentProgram)
mips_rop.find_controllable_calls()

sleep_calls = mips_rop.find_instructions([li_a0])

sleep_calls.pretty_print()
