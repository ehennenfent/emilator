from llilvisitor import LLILVisitor
import errors

def _make_token(func_name, index):
    return '{}:{}'.format(func_name, index)

class DebuggerVisitor(LLILVisitor):
    def __init__(self, **kwargs):
        super(DebuggerVisitor, self).__init__(**kwargs)
        self._breakpoints = {}

    def visit(self, expression):
        breakpoint = self._breakpoints.get(_make_token(expression.function.source_function.name, self.instr_index))

        if breakpoint:
            self.instr_index -= 1
            breakpoint(self, expression)
            raise errors.BreakpointHit()
        else:
            result = super(DebuggerVisitor, self).visit(expression)

        if result is None:
            raise errors.UnimplementedError(expression.operation)

        return result

    def set_breakpoint(self, func_name, index, callback=None):
        if callback is not None:
            self._breakpoints[_make_token(func_name, index)] = callback
        else:
            self._breakpoints[_make_token(func_name, index)] = lambda j,k: k
