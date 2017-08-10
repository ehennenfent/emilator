from binaryninja import *
from emilator import Emilator
import coverage
from util import *

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: test.py <binary file>")
        exit(1)

    bv = BinaryViewType.get_view_of_file(sys.argv[1])
    main = bv.symbols['_start'].address
    main = bv.get_function_at(main)

    il = main.low_level_il
    emi = Emilator(il, view=bv)
    coverage.test_coverage(emi)

    for reg in sorted(bv.arch.full_width_regs):
        emi.set_register_value(reg, 0)

    emi.set_register_value('rbp', 0x90000)
    emi.set_register_value('rsp', 0x50000)

    print '[+] Mapping memory at 0x1000 (size: 0x1000)...'
    emi.map_memory(start=0x0, length=0x100000)

    print '[+] Initial Register State:'
    dump_registers(emi)

    print '[+] Instructions:'
    for i in range(len(emi.function)):
        print '{}\t{}'.format(il[i].instr_index, repr(il[i]))

    print '[+] Executing instructions...'
    for i in emi.run():
        print '\tInstruction {} completed: {} -- {}'.format(i.instr_index, i, i.operation.name)

    print '[+] Final Register State:'
    dump_registers(emi)
