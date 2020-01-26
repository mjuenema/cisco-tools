#!/usr/bin/env python3

# service 
#   unsupported-transceiver
# hostname 
#   B01
# clock 
#   timezone 
#     AEST
#       10
#   summer-time
#     ADST
#       recurring
#         first
#           sunday
#             october
#               02:00
#                 first
#                   sunday
#                     april
#                       03:00
# banner
#   login

import sys
import pprint
import yaml
import json


def parse(data, tokens):
    if tokens == []:
        return data

    token = tokens.pop(0)

    if not token in data:
        data[token] = {}

    data[token] = parse(data[token], tokens)

    return data


def skip_banner(fp, separator):
   # Read over Cisco banner
   while True:
       line = fp.readline()
       if separator in line:
           break


#def read_line(fp, prefix, indent):
#    line = fp.readline().rstrip()
#
#    if line is None:
#        sys.exit()
#
#    print(prefix + ' ' + line, end='')
#
#    this_indent = len(line)-len(line.strip(' '))
#
#    if this_indent == indent:
#        read_line(fp, prefix, this_indent)
#    elif this_indent > indent:
#        prefix = prefix + ' ' + line
#        read_line(fp, prefix, this_indent)
#    else:
#        print('\n')
#        return



contexts = {}
lines = []
data = {}

with open(sys.argv[1], 'rt') as fp:
    for this_line in fp:

        this_line = this_line.rstrip()

        if '!' in this_line:
            continue

        if this_line.startswith('banner'):
            separator = this_line.split()[-1]
            skip_banner(fp, separator)
            continue

        if this_line.startswith('end'):
            continue

        this_indent = len(this_line)-len(this_line.strip(' '))

        contexts[this_indent] = this_line

        prefixes = [contexts[i] for i in range(0,this_indent)]
        line = ' '.join(prefixes + [this_line])


        tokens = line.strip().split()
        data = parse(data, tokens)

print(json.dumps(data, indent=2))
#print(data['vrf'].keys())






#        this_line = this_line.rstrip()
#        this_indent = len(this_line)-len(this_line.strip(' '))
#
#        # Convert comment lines into empty lines
#        if '!' in this_line:
#            this_line = ''
#
#        print(this_indent, this_line)
#
#        if this_line.startswith('banner'):
#            separator = this_line.split()[-1]
#            skip_banner(fp, separator)
#            continue
#
#        if this_indent > last_indent:
#            prefixes.append(last_line.strip())
#            output = None
#
#        if this_indent < last_indent:
#            prefixes = prefixes[:-1]
#
#
#
##        if this_indent <= last_indent:
##            output = (' '.join(prefixes) + ' ' + this_line).strip()
#
##        if output:
##            print(output)
#
##        print(prefixes)
#
##        line = (' '.join(prefixes) + ' ' + this_line).strip()
##        print(line)
#
#        last_indent = this_indent
#        last_line = this_line
#
##        print('>', this_indent, line)
#
#    sys.exit()
#
#
#    n = 0
#    for line in fp:
#       n += 1
#
#       if line.startswith('!'):
#           continue
#
#       tokens = line.strip().split()
#      
#       # Read over Cisco banner
#       if tokens[0] == 'banner':
#           sep = tokens[-1]
#
#           while True:
#               line = fp.readline()
#               if sep in line:
#                   break
#           continue
#
#       data = parse(data, tokens)
#
##       if n > 10:
##           break
#
#    #print(yaml.dump(data))
#
##    print(dir(data))
#
#    print(data['clock.timezone'])
#
#    #data.clean()
#
#    print(data['clock.timezone'])
#
#    #data.standardize()
#    print(data.to_json(indent=2))


       


