# Find ARM ROP gadgets that move values between registers.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Register Movement


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

src_reg = askChoice('Source Register',
                    'What source register do you want to move?',
                    ['Any', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5',
                        'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
                    'Any')

dest_reg = askChoice('Destination Register',
                     'Where do you want the source to be moved?',
                     ['Any', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5',
                         'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
                     'Any')

print "Searching for gadgets that move %s to %s" % (src_reg, dest_reg)

if src_reg == 'Any':
    src_reg = '^(r[01]?\d)'
else:
    src_reg += '$'

if dest_reg == 'Any':
    dest_reg = '^(r[01]?\d)'
else:
    dest_reg += '$'


cpy_reg = armrop.ArmInstruction('cpy', dest_reg, src_reg)
move_reg = armrop.ArmInstruction('mov', dest_reg, src_reg)

arm_rop = armrop.ArmRop(currentProgram)
stack_finders = arm_rop.find_instructions([cpy_reg, move_reg])

stack_finders.pretty_print()
