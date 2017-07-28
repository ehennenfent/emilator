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
    main = bv.symbols['main'].address
    main = bv.get_function_at(main)

    il = main.low_level_il
    emi = Emilator(il, view=bv)
    coverage.test_coverage(emi)

    for reg in sorted(bv.arch.full_width_regs):
        emi.set_register_value(reg, 0)

    emi.set_register_value('ebp', 0x200)
    emi.set_register_value('esp', 0x100)

    print '[+] Mapping memory at 0x1000 (size: 0x1000)...'
    emi.map_memory(start=0x0)

    print '[+] Initial Register State:'
    dump_registers(emi)

    print '[+] Instructions:'
    for i in range(len(emi.function)):
        print '{}\t{}'.format(il[i].instr_index, repr(il[i]))

    print '[+] Executing instructions...'
    for count, i in enumerate(emi.run()):
        print '\tInstruction {} completed'.format(count)

    print '[+] Final Register State:'
    dump_registers(emi)
