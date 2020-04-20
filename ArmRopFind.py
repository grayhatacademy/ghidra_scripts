# Find ARM ROP gadgets that contain a user specified instruction.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Find


import re
from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

op1 = None
op2 = None
op3 = None

search = askString(
    'ARM ROP Find', 'What instruction do you want to search for?')
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

print 'Searching for %s' % search
search_ins = armrop.ArmInstruction(mnem, op1, op2, op3)

arm_rop = armrop.ArmRop(currentProgram)
results = arm_rop.find_instructions([search_ins])

results.pretty_print()
