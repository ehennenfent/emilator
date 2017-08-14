from prompt_toolkit import prompt
from prompt_toolkit.contrib.completers import WordCompleter
from debugger import *
import argparse
import traceback

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('binary', type=str, help='A binary or .bndb')
parser.add_argument("arguments", help="arguments to pass to the binary (unsupported)", nargs="?")
arguments = parser.parse_args()

cmd_map = [
    (['quit', 'q', 'exit'], exit_wrapper),
    (['nexti', 'ni'], step_over),
    (['stepi', 'si'], step_in),
    (['continue', 'c'], continue_to),
    (['break', 'b'], breakpoint),
    (['finish'], finish),
    (['run', 'r'], run),
    (['kill', 'ki', 'k'], kill),
    (['info', 'i',], info),
]

def dispatch(verb, args):
    found = False
    for entry in cmd_map:
        if verb in entry[0]:
            found = True
            try:
                entry[1](args)
                break
            except:
                traceback.print_exc()
                break
    if not found:
        print("No such command: {}".format(verb))

if __name__ == '__main__':
    load_binary(arguments.binary, arguments.arguments)
    cmd_completer = WordCompleter([cmd for item in cmd_map for cmd in item[0] if len(cmd) > 2])
    while(True):
        answer = prompt(u'(emILator) ', completer = cmd_completer)
        lexed = answer.split(' ')
        if len(lexed) == 1:
            dispatch(lexed[0], [])
        elif len(lexed) > 1:
            dispatch(lexed[0], lexed[1:])
