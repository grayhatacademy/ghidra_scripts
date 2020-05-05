# Display call chain graph between two functions and output to the console.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Call Chain

import os
import sys
import tempfile
from utils import graphviz

from ghidra.util.graph import DirectedGraph, Vertex, Edge
from ghidra.graph.viewer import GraphComponent
from ghidra.app.services import GraphService

found_call_chain = False


def get_references(caller, callee):
    """
    Find reference addresses between a caller function and callee function.

    :param caller: Caller function.
    :param callee: Callee function.

    :return: List of addresses where the caller calls the callee.
    :rtype: list
    """
    function_manager = currentProgram.getFunctionManager()

    ref_list = []
    callee_symbol = callee.getSymbol()
    callee_references = callee_symbol.getReferences()

    for ref in callee_references:
        addr = ref.getFromAddress()
        func = function_manager.getFunctionContaining(addr)
        if func == caller:
            ref_list.append(addr)

    return ref_list


def sanitize_dot(func):
    """
    Return a sanitized function name string compatible with DOT representation.

    :param func: Function object
    """
    return str(func).replace("::", "\\")


def print_call_chain(call_chain, dot):
    """
    Print successful call chains to the console and add to the graph.

    :param call_chain: Successful call chain.
    :param dot: Call graph.
    """
    previous_function = None
    function_references = {}
    function_chain = []

    for function in call_chain:
        references = []

        function_name = sanitize_dot(function)

        if function == call_chain[0]:
            dot.node(function_name, str(function), style='filled',
                     color='blue', fontcolor='white')
        elif function == call_chain[-1]:
            dot.node(function_name, str(function), style='filled',
                     color='red', fontcolor='white')
        else:
            dot.node(function_name, str(function))
        if previous_function:
            previous_function_name = sanitize_dot(previous_function)
            dot.edge(previous_function_name, function_name)
            function_references[str(previous_function)] = get_references(
                previous_function, function)

        previous_function = function
        function_chain.append(str(function))

    for function in function_chain:
        print function,
        if function in function_references:
            print function_references[function],
            print ' -> ',
    print ''


def call_chain_recurse(call_chain, complete_call, dot):
    """
    Recurse from call_chain to complete_call, if found.

    :param call_chain: Current call chain.
    :param complete_call: Call that indicates a successfully completed chain.
    :param dot: Call graph
    """
    global found_call_chain

    function_list = call_chain[0].getCallingFunctions(monitor)
    for func in function_list:
        if func == complete_call:
            print_call_chain([func] + call_chain, dot)
            found_call_chain = True
            continue

        if func in call_chain:
            continue
        call_chain_recurse([func] + call_chain, complete_call, dot)


def discover_call_chain(from_function, to_function):
    """
    Discover call chains between two functions.

    :param from_function: Function start looking for path to next function.
    :param to_function: Function that, when/if found, indicates a chain.
    """
    dot = graphviz.Digraph('Function Paths', format='png', strict=True)
    call_chain_recurse([to_function], from_function, dot)

    if found_call_chain:
        tmp_file = tempfile.mktemp()
        dot.render(tmp_file, view=True)


func_man = currentProgram.getFunctionManager()
function_list = [function for function in func_man.getFunctions(True)]
function_list.sort(key=lambda func: str(func))

from_function = askChoice('Select function',
                          'Select the starting function',
                          function_list,
                          function_list[0])

function_list.remove(from_function)
to_function = askChoice('Select function',
                        'Select the ending function',
                        function_list,
                        function_list[0])

print 'Finding x-refs from %s to %s\n' % (from_function, to_function)

discover_call_chain(from_function, to_function)
