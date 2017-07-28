from binaryninja import *
from emilator import Emilator
import coverage

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: test.py <binary file>")
        exit(1)

    bv = BinaryViewType.get_view_of_file(sys.argv[1])
    main = bv.symbols['main'].address
    main = bv.get_function_at(main)

    il = main.low_level_il
    emi = Emilator(il)
    coverage.test_coverage(emi)

    for reg in sorted(bv.arch.full_width_regs):
        emi.set_register_value(reg, 0)

    emi.set_register_value('esp', 0x1000)

    print '[+] Mapping memory at 0x1000 (size: 0x1000)...'
    emi.map_memory(0x1000, flags=SegmentFlag.SegmentReadable)

    print '[+] Initial Register State:'
    for r, v in emi.registers.iteritems():
        print '\t{}:\t{:x}'.format(r, v)

    print '[+] Instructions:'
    for i in range(len(emi.function)):
        print '{}\t{}'.format(il[i].instr_index, repr(il[i]))

    print '[+] Executing instructions...'
    for i in emi.run():
        print '\tInstruction completed.'

    print '[+] Final Register State:'
    for r, v in emi.registers.iteritems():
        print '\t{}:\t{:x}'.format(r, v)
