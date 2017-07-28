from binaryninja import LowLevelILInstruction

ops = LowLevelILInstruction.ILOperations

def test_coverage(emi, verbose=False):
    covered = set()
    uncovered = set()

    for operation in filter(lambda k: '_SSA' not in k.name and '_PHI' not in k.name, ops.keys()):
        if hasattr(emi, 'visit_{}'.format(operation.name)):
            covered.add(operation)
        else:
            uncovered.add(operation)

    if verbose:
        print("Instructions covered:")
        for inst in covered:
            print("\t{}".format(inst.name))
        print("Instructions missing:")
        for inst in uncovered:
            print("\t{}".format(inst.name))
    print "Emilator covers {0}/{1} non-SSA LLIL instructions".format(len(covered), len(covered) + len(uncovered))
    return covered, uncovered

function_template = """
def visit_{op}(self, expr):
{args}    return None"""

def generate_uncovered_instruction_templates(emi):
    _, uncovered = test_coverage(emi, verbose=True)

    for op in uncovered:
        insert = ""
        args = ops[op]
        for arg in args:
            insert += "    {0} = self.visit(expr.{0})\n".format(arg[0])

        print function_template.format(op=op.name, args=insert)


if __name__ == '__main__':
    from binaryninja import LowLevelILFunction, Architecture
    from emilator import Emilator

    il = LowLevelILFunction(Architecture['x86_64'])
    emi = Emilator(il)

    generate_uncovered_instruction_templates(emi)
