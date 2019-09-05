# Find MIPS ROP gadgets that perform an indirect return. (Call t9, return to ra.)
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Indirect Return


from utils import mipsrop

move_t9 = mipsrop.MipsInstruction('.*move', 't9', '[sav][012345678]')

mips_rop = mipsrop.MipsRop(currentProgram)
indirect_returns = mips_rop.find_instructions(
    [move_t9], controllable_calls=False)

indirect_returns.pretty_print()
