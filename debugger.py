from __future__ import print_function
from binaryninja import *
from emilator import Emilator
import coverage
from util import *

llil = None
emilator = None
bv = None

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
    global emilator, bv
    ### TODO: Implement platform-dependent loading conventions accurate to the real thing
    for reg in sorted(bv.arch.full_width_regs):
        emilator.set_register_value(reg, 0)
    emilator.set_register_value('rbp', 0xf0000)
    emilator.set_register_value('rsp', 0xf0000)
    emilator.map_memory(start=0x0, length=0x100000)

    for i in emilator.run():
        print('{}:{} completed: {} -- {}'.format(i.function.source_function.name, i.instr_index, i, i.operation.name))


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
    global emilator, llil, bv

    bv = BinaryViewType.get_view_of_file(binary)
    start = bv.symbols['_start'].address
    start = bv.get_function_at(start)

    llil = start.low_level_il
    emilator = Emilator(llil, view=bv)
