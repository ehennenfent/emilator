class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()
        self.instr_index = 0

    def visit(self, expression):
        method_name = 'visit_{}'.format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            value = None
        return value
