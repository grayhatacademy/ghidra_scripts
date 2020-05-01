from . import mipsrop, utils

REGISTERS = ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8']


def get_chain_length(chain):
    return sum(map(len, chain))


class ChainLink(object):
    def __init__(self, name, gadget, control_gadget=None):
        self.name = name
        self._gadget = gadget
        self._control_gadget = control_gadget
        self.chain = []
        self.control_gained = {}
        self.overwritten = {}
        self.jump_register = {}
        self.action_register = {}

        # Double jumps need to be handled different from single jump gadgets.
        if isinstance(gadget, mipsrop.DoubleGadget):
            # Ignoring control gadgets for double jumps. Makes everything
            # more complicated. Might come back to this.
            if control_gadget:
                pass
            else:
                jump_one = gadget.first.get_source_register()
                jump_two = gadget.second.get_source_register()
                action_one = gadget.first.get_source_register()
                action_two = gadget.second.get_source_register()

                self.jump_register[jump_one] = \
                    gadget.first.call.getAddress()
                self.jump_register[jump_two] = \
                    gadget.second.call.getAddress()
                self.action_register[action_one] = \
                    gadget.first.control_instruction.getAddress()
                self.action_register[action_two] = \
                    gadget.second.control_instruction.getAddress()
        else:
            if control_gadget:
                control_reg = control_gadget.get_action_source_register()
                action_reg = gadget.get_action_destination_register()
                control_jump = control_gadget.get_action_source_register()
                gadget_jump = control_gadget.jump.get_control_item()

                self.action_register[control_reg] = \
                    control_gadget.action.getAddress()

                self.action_register[action_reg] = gadget.action.getAddress()

                self.jump_register[control_jump] = \
                    control_gadget.action.getAddress()

                self.jump_register[gadget_jump] = \
                    control_gadget.jump.control_instruction.getAddress()

                self.chain.append(control_gadget)
            else:
                gadget_jump = gadget.jump.get_control_item()
                action = gadget.get_action_source_register()
                self.jump_register[gadget_jump] = \
                    gadget.jump.control_instruction.getAddress()
                self.action_register[action] = gadget.action.getAddress()

        self.chain.append(gadget)
        self._get_registers_overwritten(gadget)
        self._validate_jumps()

    def __len__(self):
        length = len(self._gadget)
        if self._control_gadget:
            length += len(self._control_gadget)
        return length

    def __eq__(self, gadget):
        if type(gadget._gadget) is not type(self._gadget):
            return False
        elif isinstance(self._gadget, mipsrop.DoubleGadget):
            pass
        else:
            return self._gadget.action.getAddress() == gadget._gadget.action.getAddress()

    def _validate_jumps(self):
        """
        Validate the gadget doesn't overwrite registers it needs to jump.

        :raises: ValueError if gadget is invalid.
        """
        for register in self.overwritten.keys():
            if register in self.jump_register.keys():
                if self.jump_register[register] < self.overwritten[register]:
                    continue
                raise ValueError

    def _get_registers_overwritten(self, gadget):
        """
        Record registers that are overwritten and which ones are controlled.
        """
        instructions = gadget.get_instructions()
        for instruction in instructions:
            reg = mipsrop.get_overwritten_register(instruction)
            if reg and reg in REGISTERS + ['a0', 'a1', 'a2', 'a3', 'sp']:
                if reg not in self.overwritten:
                    self.overwritten[reg] = instruction.getAddress()
                if reg in self.control_gained:
                    self.control_gained.pop(reg)
                if 'lw' in str(instruction) and 'sp' in str(instruction):
                    self.control_gained[reg] = instruction.getAddress()

    def get_action_destination(self):
        """
        Return the gadgets action destination register. Uses the gadget and not
        the control gadget because the whole purpose of the control gadget is 
        calling the actual gadget.

        :returns: Action destination register. 
        """
        return self._gadget.get_action_destination_register()

    def print_gadget(self, extended=False):
        """
        Print the gadget
        """
        title = self.name
        if self._control_gadget:
            title += ' (Control Gadget Required)'
            print title
            print '-' * len(title)
            print 'Control Gadget:'
            self._control_gadget.print_instructions()
            print '\n'
            print 'Gadget:'
        else:
            print title
            print '-' * len(title)

        self._gadget.print_instructions()
        if extended:
            print '\nControl Gained\n-------------'
            print self.control_gained
            print '\nOvewritten Registers\n-----------'
            print self.overwritten
            print '\nJump Register\n-------------'
            print self.jump_register
            print '\nAction Source\n-------------'
            print self.action_register
            try:
                print '\nAction Destination\n-------------'
                print self.get_action_destination()
            except:
                pass
        print '\n'


class GadgetLinks(object):
    def __init__(self, name, rop_finder, gadgets, check_control=True,
                 destination_generation=False):
        self.name = name
        self._rop_finder = rop_finder
        self._links = gadgets
        self.destination_generation = destination_generation
        self.chains = []

        for gadget in self._links:
            try:
                gadget_chain = ChainLink(name, gadget)
            except ValueError:
                continue

            jump_reg = gadget_chain.jump_register.keys()
            if check_control and jump_reg[0] not in REGISTERS and 'sp' not in jump_reg:
                control_links = self._find_control_jump(jump_reg[0])
                for control in control_links:
                    try:
                        gadget_chain = ChainLink(name, gadget, control)
                        self.chains.append(gadget_chain)
                    except ValueError:
                        continue
            else:
                self.chains.append(gadget_chain)

    def _find_control_jump(self, jump_register):
        """
        Find gadget that, when called, grants control of the current gadget.

        :param jump_register: Register control required to use this gadget. 
        :type jump_register: str 

        :returns: Gadgets that grant control of the jump register
        """
        ins = mipsrop.MipsInstruction('.*mov', jump_register, '.*s')
        control = self._rop_finder.find_instructions([ins])
        return control.gadgets

    def find_gadget(self, controlled_registers):
        """
        Find usable gadgets based on currently controlled registers.

        :param controlled_registers: List of currently controlled registers.
        :type controlled_registers: list(str)

        :returns: List of gadgets that can be used based on the controlled 
                  registers.
        """
        gadgets = []
        for gadget in self.chains:
            add = True
            for jump in gadget.jump_register:
                if 'sp' in jump:
                    continue

                if jump not in controlled_registers:
                    add = False
                    break
            if add:
                gadgets.append(gadget)
        return gadgets


def update_available_registers(registers, gadget):
    """
    Update available registers list based on what gadget does.

    :param registers: List of currently controlled registers.
    :type registers: list(str)

    :param gadget: Current gadget.
    :type gadget: GadgetChain

    :returns: New list of available registers.
    :rtype: list(str)
    """
    new_registers = registers[:]

    try:
        for jump in gadget.jump_register:
            if 'sp' not in jump:
                new_registers.remove(jump)
    except ValueError:
        return []

    for reg in gadget.overwritten:
        try:
            new_registers.remove(reg)
        except ValueError:
            pass

    for reg in gadget.control_gained:
        if reg not in registers:
            new_registers.append(reg)
    return new_registers


class ChainBuilder(object):
    def __init__(self, rop_finder, registers_controlled, chain_limit,
                 allow_reuse, verbose):
        self._rop_finder = rop_finder
        self._registers = registers_controlled
        self._allow_reuse = allow_reuse
        self._verbose = verbose
        self.gadgets = []
        self.chains = []
        self.chain_len = 0
        self.chain_limit = chain_limit
        self.max_chain = 0

    def add_gadgets(self, name, gadget, check_control=True,
                    destination_generation=False, index=None):
        """
        Add new gadget to the chain builder.

        :param name: Name of the gadget. Only used for printing purposes.
        :type name: str

        :param gadget: List of available gadgets.
        :type gadget:

        :param check_control: If the gadget jump is not controllable by a saved
                             register then search for a gadget to gain control.
        :type check_control: bool

        :param destination_generation: Gadget should be chosen based on the action
                                       of the previous gadget instead of the 
                                       currently controlled registers.
        :type destination_generation: bool

        :param index: Index to insert gadget. Index dictates it position in the 
                      generated chain.
        :type index: int
        """
        gadget_links = GadgetLinks(
            name, self._rop_finder, gadget, check_control,
            destination_generation)
        if index is not None:
            self.gadgets.insert(index, gadget_links)
        else:
            self.gadgets.append(gadget_links)

    def generate_chain(self):
        """
        Generate a ROP chain based on the provided gadgets.
        """
        self._process_links(
            self.gadgets[0], self._registers, self.gadgets[1:], [])
        if not self.chains and self._verbose:
            print 'ERROR: Looks like no chains were found. Failed to find ' + \
                'working gadget for "%s"' % self.gadgets[self.max_chain].name

    def display_chains(self, verbose):
        """
        Pretty print the discovered chains.
        """
        for i in range(len(self.chains)):
            title = 'Chain %d of %d (%d instructions)' % \
                (i + 1, len(self.chains), get_chain_length(self.chains[i]))
            print '\n'
            print '*' * len(title)
            print title
            print '*' * len(title)
            for gadget in self.chains[i]:
                gadget.print_gadget(verbose)

    def _add_new_chain(self, new_chain):
        """
        Add a new chain to the saved list and drop longer chains that are above
        the search limit.

        :param new_chain: Chain to add to the list.
        :type new_chain: list(GadgetChain)
        """
        chain_length = get_chain_length(new_chain)
        if self._verbose:
            print 'Found new chain of length %d' % chain_length
        self.chains.append(new_chain)
        self.chains.sort(key=lambda chain: get_chain_length(chain))
        self.chains = self.chains[:self.chain_limit]

    def _above_max_len(self, length):
        """
        Check if length is above the longest chain saved. Automatically passes
        if the chain limit has not been reached.

        :return: True if above the limit, else False.
        :rtype: bool
        """
        if len(self.chains) < self.chain_limit:
            return False
        if length < get_chain_length(self.chains[-1]):
            return False
        return True

    def _gadget_is_used(self, gadget):
        """
        Check if gadget is used in a saved chain.

        :param gadget: Gadget to search for.
        :type gadget: GadgetChain

        :returns: True if gadget is used in a saved chain, False otherwise.
        :rtype: bool
        """
        for chain in self.chains:
            for used_gadget in chain:
                if gadget == used_gadget:
                    return True
        return False

    def _process_links(self, links, registers, remaining_links, chain):
        """
        Recursively search through gadgets to build a chain.

        :param links: Current links to search for next gadget.
        :type links: GadgetLinks

        :param registers: Currently controlled registers.
        :type registers: list(str)

        :param remaining_links: Links left to use.
        :type remaining_links: list(GadgetLinks)

        :param chain: Current chain.
        :type chain: list(GadgetLink)
        """
        if self._above_max_len(get_chain_length(chain)):
            return

        self.max_chain = max([self.max_chain, len(chain)])
        available_links = links.find_gadget(registers)
        if not available_links and self._verbose:
            print 'No gadgets found with control of %s in %s' % (registers,
                                                                 links.name)

        current_chain = chain[:]
        for gadget in available_links:
            # Not a perfect solution, but provides a little variety to chains
            # if multiple are requested. Might not find the shortest because of
            # that.
            if not self._allow_reuse and self._gadget_is_used(gadget):
                continue

            current_chain.append(gadget)
            if remaining_links:
                if remaining_links[0].destination_generation:
                    register_control = [gadget.get_action_destination()]
                else:
                    register_control = update_available_registers(
                        registers, gadget)
                self._process_links(
                    remaining_links[0], register_control, remaining_links[1:],
                    current_chain)
            else:  # No remaining links mean the chain is complete.
                self._add_new_chain(current_chain[:])
                return
            current_chain.pop()
