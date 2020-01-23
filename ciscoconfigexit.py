#!/usr/bin/env python3

import sys

try:
    with open(sys.argv[1], 'rt') as fp:
        lines = [line.rstrip() for line in fp.read().split('\n')]

    old_indent = new_indent = 0

    for line in lines:


        new_indent = len(line) - len(line.lstrip())

        if new_indent < old_indent:
            print(' ' * old_indent + 'exit')
        print(line)

        old_indent = new_indent

except IndexError:
    print('Usage: {} <configfile>'.format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(e, file=sys.stderr)
    sys.exit(2)
