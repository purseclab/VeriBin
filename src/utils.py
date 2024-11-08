from difflib import SequenceMatcher
from argparse import ArgumentTypeError
import claripy

# Store a dictionary of colors.
COLOR = {
    'green': '\033[92m',
    'red': '\033[91m',
    'reset': '\033[0m'
}

# Overload the print function to truncate the output if it exceeds N bytes
try:
    import __builtin__
except ImportError:
    # Python 3
    import builtins as __builtin__

def print(*args, n=5000):
    """
    Custom print function that truncates the output if it exceeds N bytes.

    Parameters:
    - *args: The values to be printed.
    - n: The maximum number of bytes to print.
        If the output exceeds this number, it will be truncated.
    """

    # Join the arguments into a single string
    msg_str = ' '.join(map(str, args))

    # If msg is too long, print the first N characters
    if len(msg_str) > n:
        msg_str = msg_str[:n] + f"\t[...] (message is too long) {COLOR['reset']}"
    return __builtin__.print(msg_str)

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise ArgumentTypeError('Boolean value expected.')

def similar(a, b):
    if not isinstance(a, str):
        a = str(a)
    if not isinstance(b, str):
        b = str(b)
    if len(a) != len(b):
        return 0
    else:
        return SequenceMatcher(None, a, b).ratio()

def is_rodata_addr(project, addr_bv):
    """
    Check if the address is in .rodata section
    :param addr:
    :return:
    """
    # If the addr_bv is not a concrete value, return False
    if not addr_bv.concrete:
        return False
    # The addr can be FPV or BVV or else,
    # We only consider BVV for now
    if addr_bv.op != 'BVV':
        return False
    # Convert the addr_bv to concrete value
    addr = addr_bv.args[0]
    section = project.loader.find_section_containing(addr)
    if section is not None:
        # if self.project.loader.memory.min_addr < val < self.project.loader.memory.max_addr:
        # '.data', '.rodata', '.bss'? Only consider .rodata for now
        if section.name in {'.rodata'}:
            return True
    return False

def load_string_content_from_binary(project, addr_bv):
    """
    Load the content of the string from binary
    :param addr: angr project, claripy address bitvector
    :return: content of the string
    """
    addr = addr_bv.args[0]
    count = 0
    expression_size = addr_bv.size()

    # Count the size of the target object until NULL (0x00)
    while True:
        value = project.loader.memory.unpack(addr + count, 'c')
        if value[0] == b'\x00':
            break
        count += 1

    if count > 0:
        try:
            content = project.loader.memory.unpack(addr, '%ds' % count)
            print("\tcount and content:", count, str(content[0]))
            content_BV = claripy.BVS("String{"+str(content[0], 'utf-8')+"}", expression_size, explicit_name=True)
            return content_BV
        except UnicodeDecodeError:
            return None
    return None