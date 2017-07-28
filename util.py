def dump_registers(emi):
    for r, v in emi.registers.iteritems():
        print '\t{}:\t{:x}'.format(r, v)
