# Identify potential POSIX functions in the current program such as strcpy, strcat, memcpy, atoi, strlen, etc.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Leaf Blower.Find leaf functions


from utils import leafblower

print 'Searching for potential POSIX leaf functions...'
leaf_finder = leafblower.LeafFunctionFinder(currentProgram)
leaf_finder.find_leaves()
leaf_finder.display()
