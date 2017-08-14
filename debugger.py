from __future__ import print_function
from binaryninja import *
from emilator import Emilator
import coverage
from util import *

llil = None
emilator = None

is_running = False

def exit_wrapper(_args):
    exit(0)

def step_over(args):
    pass

def step_in(args):
    pass

def breakpoint(args):
    pass

def continue_to(args):
    pass

def finish(_args):
    pass

def run(_args):
    pass

def kill(_args):
    pass

def info(args):
    if len(args) == 0:
        print("Usage: info [property]")
        return
    target = args[0]
    if target in ['r', 'registers']:
        dump_registers(emilator)
    elif target in ['coverage']:
        coverage.test_coverage(emilator, verbose=True)

def load_binary(binary, _args):
    global emilator
    global llil

    bv = BinaryViewType.get_view_of_file(binary)
    start = bv.symbols['_start'].address
    start = bv.get_function_at(start)

    llil = start.low_level_il
    emilator = Emilator(llil, view=bv)
