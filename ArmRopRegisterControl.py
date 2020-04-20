# Find ARM ROP gadgets that give control of registers by popping them off the stack.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Arm Rop.Register Control


from utils import armrop, utils

utils.allowed_processors(currentProgram, 'ARM')

reg = askChoice('Source Register',
                'What register do you want to control?',
                ['Any', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
                 'r9', 'r10', 'r11', 'r12'],
                'Any')

if reg == 'Any':
    print 'Searching for gadgets that give control of any register.'
    reg = '.*(r[01]?\d).*'
else:
    print 'Searching for gadgets that give control of %s.' % reg

reg = '.*' + reg + ' .*'

reg_control = armrop.ArmInstruction('ldmia', 'sp!', reg)

arm_rop = armrop.ArmRop(currentProgram)
control = arm_rop.find_instructions([reg_control], controllable_calls=False)

control.pretty_print()
