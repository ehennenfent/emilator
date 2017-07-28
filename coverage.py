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
            print("    {}".format(inst.name))
        print("Instructions missing:")
        for inst in uncovered:
            print("    {}".format(inst.name))
    print "Emilator covers {0}/{1} non-SSA LLIL instructions".format(len(covered), len(covered) + len(uncovered))
