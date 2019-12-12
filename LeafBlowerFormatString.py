# Identify potential POSIX functions in the current program such as sprintf, fprintf, sscanf, etc.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Leaf Blower.Find format string functions


from utils import leafblower

print 'Searching for format string functions...'
format_string_finder = leafblower.FormatStringFunctionFinder(currentProgram)
format_string_finder.find_functions()
format_string_finder.display()
