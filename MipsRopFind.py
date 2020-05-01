# Find MIPS ROP gadgets that contain a user specified instruction.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Mips Rops.Gadgets.Find


import re
from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

op1 = None
op2 = None
op3 = None

search = askString(
    'MIPS ROP Find', 'What instruction do you want to search for?')
try:
    search = re.sub(' +', ' ', search)
    mnem, operands = search.split(' ', 1)
    operands = operands.replace(' ', '')
    operands = operands.split(',')
    op1, op2, op3 = operands + [None] * (3 - len(operands))
except ValueError:
    mnem = search

if not mnem.startswith('.*'):
    mnem = '.*' + mnem

search_ins = mipsrop.MipsInstruction(mnem, op1, op2, op3)

mips_rop = mipsrop.MipsRop(currentProgram)
results = mips_rop.find_instructions([search_ins])

results.pretty_print()
