import bitstruct

def dump_registers(emi):
    for r, v in sorted(emi.registers.iteritems(), key=lambda k: k[0]):
        print '\t{}:\t{:x}'.format(r, v)

def unsignify(val, length=32):
    return bitstruct.unpack('u{}'.format(length), bitstruct.pack('s{}'.format(length), val))[0]

def signify(val, length=32):
    return bitstruct.unpack('s{}'.format(length), bitstruct.pack('u{}'.format(length), val))[0]
