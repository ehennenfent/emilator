from binaryninja import LowLevelILInstruction, MediumLevelILInstruction
import bitstruct

def dump_registers(emi):
    for r, v in sorted(emi.registers.iteritems(), key=lambda k: k[0]):
        print '\t{}:\t{:x}'.format(r, v)

def unsignify(val, length=32):
    return bitstruct.unpack('u{}'.format(length), bitstruct.pack('s{}'.format(length), val))[0]

def signify(val, length=32):
    return bitstruct.unpack('s{}'.format(length), bitstruct.pack('u{}'.format(length), val))[0]

def il_pprint(instruction, depth=0):
    if type(instruction) is list:
        partial = ''
        for idx, item in enumerate(instruction):
            partial += '\n' + '\t'*(depth+1) + '{}: {}'.format(idx, il_pprint(item, depth+1))
        out = '[]' if len(instruction) == 0 else '[{}'.format(partial) + '\n' + '\t'*depth + ']'
    elif type(instruction) not in [LowLevelILInstruction, MediumLevelILInstruction]:
        return '{} {}'.format(type(instruction).__name__, instruction)
    else:
        out = '{} -- ({})'.format(instruction.operation.name, instruction)
        keys = LowLevelILInstruction.ILOperations[instruction.operation] if type(instruction) == LowLevelILInstruction else MediumLevelILInstruction.ILOperations[instruction.operation]
        for key in keys:
            out += '\n' + '\t'*(depth+1) + '{}: {}'.format(key[0], il_pprint(getattr(instruction, key[0]), depth+1))
    if depth == 0:
        print(out)
    return out
