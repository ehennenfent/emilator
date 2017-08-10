def dump_registers(emi):
    for r, v in sorted(emi.registers.iteritems(), key=lambda k: k[0]):
        print '\t{}:\t{:x}'.format(r, v)
