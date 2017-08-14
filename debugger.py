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
    pass

def load_binary(binary, _args):
    global emilator
    global llil

    bv = BinaryViewType.get_view_of_file(binary)
    start = bv.symbols['_start'].address
    start = bv.get_function_at(start)

    llil = start.low_level_il
    emilator = Emilator(llil, view=bv)
    coverage.test_coverage(emilator)
