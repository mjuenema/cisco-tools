#!/usr/bin/env python

"""


    access-list 
      access_list_name 
      [line line_number] 
      extended 
      {deny | permit} 
      protocol_argument 
      source_address_argument 
      dest_address_argument 
      [log [[level] [interval secs] | disable | default]]
      [time-range time_range_name]
      [inactive] 

"""

DEBUG = False

import sys
import socket
import ipaddress
import netaddr
import pprint

# Import different versions on PyParsing depending
# on the second command line argument.
try:
    import cPyparsing as pp
except ImportError:
    import pyparsing as pp
pp.ParserElement.enablePackrat()

## Names to number tables for TCP/UDP ports and protocols like (icmp, IP, TCP, UPD).
## Only names that cannot be resolved through `getservbyname()` listed here.
## https://community.cisco.com/t5/firewalls/cisco-asa-acl-built-in-port-name-to-number-mapping/td-p/1709769



class Rule:
    name = None
    line = None
    type = None
    action = None
    protocol = None
    source = None
    destination = None
    source_port = None
    destination_port = None
    hits = None
    hash = None
    remark = None

    @property
    def proto(self):
        return self.protocol

    @property
    def src(self):
        return self.source

    @property
    def dest(self):
        return self.destination
    dst = dest

    @property
    def sport(self):
        return self.source_port

    @property
    def dport(self):
        return self.destination_port
    port = service = dport

    @property
    def hitcnt(self):
        return self.hits

    @property
    def comment(self):
        return self.comment

class Name(str):
    pass

class Line(int):
    pass

class Type(str):
    pass

class Action(str):
    pass

class Protocol(str):
    pass

class _IPSet(netaddr.IPSet):
    pass

class Source(_IPSet):
    pass

class Destination(_IPSet):
    pass

class _Port(object):
    pass

class SourcePort(_Port):
    pass

class DestinationPort(_Port):
    pass

class Hits(int):
    pass

class Hash(str):
    pass

class Remark(str):
    pass



class Parser(object):

    def name(self, tokens):
        return None

    def type(self, tokens):
        return None

    def action(self, tokens):
        return None

    def protocol(self, tokens):
        return None

    def source(self, tokens):
        return None

    def source_port(self, tokens):
        return None

    def destination(self, tokens):
        return None

    def destination_port(self, tokens):
        return None

    def logging(self, tokens):
        return None

    def activation(self, tokens):
        return None

    def hash(self, tokens):
        return None

    def linenumber(self, tokens):
        return None

    def hitcnt(self, tokens):
        return None

    def __init__(self):

        # Keywords
        #
        k_access_list = pp.Keyword('access-list').setName('k_access_list').setDebug(DEBUG)
        k_any4 = pp.Keyword('any4').setName('k_any4').setDebug(DEBUG)
        k_any6 = pp.Keyword('any6').setName('k_any6').setDebug(DEBUG)
        k_any = pp.Keyword('any').setName('k_any').setDebug(DEBUG)
        k_deny = pp.Keyword('deny').setName('k_deny').setDebug(DEBUG)
        k_eq = pp.Keyword('eq').setName('k_eq').setDebug(DEBUG)
        k_extended = pp.Keyword('extended').setName('k_extended').setDebug(DEBUG)
        k_gt = pp.Keyword('gt').setName('k_gt').setDebug(DEBUG)
        k_hitcnt = pp.Keyword('hitcnt').setName('k_hitcnt').setDebug(DEBUG)
        k_host = pp.Keyword('host').setName('k_host').setDebug(DEBUG)
        k_icmp = pp.Keyword('icmp').setName('k_icmp').setDebug(DEBUG)
        k_interval = pp.Keyword('k_interval').setName('').setDebug(DEBUG)
        k_ip = pp.Keyword('ip').setName('k_ip').setDebug(DEBUG)
        k_line = pp.Keyword('line').setName('k_line').setDebug(DEBUG)
        k_log = pp.Keyword('log').setName('k_log').setDebug(DEBUG)
        k_lt = pp.Keyword('lt').setName('k_lt').setDebug(DEBUG)
        k_permit= pp.Keyword('permit').setName('k_permit').setDebug(DEBUG)
        k_range = pp.Keyword('range').setName('k_range').setDebug(DEBUG)
        k_standard = pp.Keyword('standard').setName('k_standard').setDebug(DEBUG)
        k_tcp = pp.Keyword('tcp').setName('k_tcp').setDebug(DEBUG)
        k_udp = pp.Keyword('udp').setName('k_udp').setDebug(DEBUG)
        k_inactive = pp.Keyword('inactive').setName('k_inactive').setDebug(DEBUG)
        k_disable = pp.Keyword('disable').setName('k_disable').setDebug(DEBUG)
        k_default = pp.Keyword('default').setName('k_default').setDebug(DEBUG)
        k_object = pp.Keyword('object').setName('k_object').setDebug(DEBUG)
        k_object_group = pp.Keyword('object-group').setName('k_object_group').setDebug(DEBUG)
        k_time_range = pp.Keyword('time-range').setName('k_time_range').setDebug(DEBUG)


        # Literals
        #
        l_close_bracket = pp.Literal(')').setName('l_close_bracket').setDebug(DEBUG)
        l_open_bracket = pp.Literal('(').setName('l_open_bracket').setDebug(DEBUG)
        l_dot = pp.Literal('.').setName('l_dot').setDebug(DEBUG)
        l_equal = pp.Literal('=').setName('l_equal').setDebug(DEBUG)


        # Tokens
        #
        t_access_list_name = pp.Word(pp.alphanums+'-'+'_').setName('t_access_list_name').setParseAction(self.name).setDebug(DEBUG)
        t_access_list_type = pp.MatchFirst([k_standard,k_extended]).setName('t_access_list_type').setDebug(DEBUG)
        t_action = pp.MatchFirst([k_permit,k_deny]).setName('t_action').setDebug(DEBUG)
        t_comparison = pp.MatchFirst([k_eq,k_gt,k_lt]).setName('t_comparison').setDebug(DEBUG)
        # some comparisons are missing
        t_hash = pp.Word(pp.alphanums).setName('t_hash').setDebug(DEBUG)
        t_hitcnt_count = pp.Word(pp.nums).setName('t_hitcnt_count').setResultsName('hitcnt').setParseAction(self.hitcnt).setDebug(DEBUG)
        t_octet = pp.Word(pp.nums, max=3).setName('t_octet').setDebug(DEBUG)
        # TODO: Use pyparsing's inbuilt IPv4 address
        t_ipaddress = pp.Combine(t_octet + l_dot + t_octet + l_dot + t_octet + l_dot + t_octet).setName('t_ipaddress').setDebug(DEBUG)
        t_netmask = pp.Combine(t_octet + l_dot + t_octet + l_dot + t_octet + l_dot + t_octet).setName('t_netmask').setDebug(DEBUG)
        t_line_number = pp.Word(pp.nums).setName('t_line_number').setParseAction(self.linenumber).setDebug(DEBUG)
        t_loginterval = pp.Word(pp.nums).setName('t_loginterval').setDebug(DEBUG)
        t_loglevel = pp.Word(pp.alphas).setName('t_loglevel').setDebug(DEBUG)
        t_port = pp.Word(pp.alphanums + '-').setName('t_port').setDebug(DEBUG)
        t_object_name = pp.Word(pp.alphanums + '_').setName('t_object_name').setDebug(DEBUG)
        t_time_range_name = pp.Word(pp.alphanums).setName('t_time_range_name').setDebug(DEBUG)


        # Line and number
        #
        c_line = k_line + t_line_number.setResultsName('line')


        # Objects and object groups
        #
        c_object = (k_object + t_object_name).setName('c_object').setDebug(DEBUG)
        c_object_group = (k_object_group + t_object_name).setName('c_object_group').setDebug(DEBUG)

        # Protocol
        #
        c_proto = pp.MatchFirst([k_ip , k_icmp , k_tcp , k_udp , c_object , c_object_group]).setName('c_proto').setDebug(DEBUG)

        # Addresses
        #
        c_address_host = (k_host + t_ipaddress).setName('c_address_host').setDebug(DEBUG)
        c_address_ipv4 = (t_ipaddress + t_netmask).setName('c_address_ipv4').setDebug(DEBUG)
        c_address_any = pp.MatchFirst([k_any , k_any4 , k_any6]).setName('c_address_any').setDebug(DEBUG)
        c_address_range = (k_range + t_ipaddress + t_ipaddress).setName('c_address_range').setDebug(DEBUG)
        c_address_object = (k_object + t_object_name).setName('c_address_object').setDebug(DEBUG)

        # Source and Destination Address
        #
        c_source = pp.MatchFirst([c_address_host , c_address_ipv4 , c_address_any , c_address_range , c_address_object]).setName('c_source').setDebug(DEBUG)
        c_destination = pp.MatchFirst([c_address_host , c_address_ipv4 , c_address_any , c_address_range , c_address_object]).setName('c_destination').setParseAction(self.destination).setDebug(DEBUG)

        # Ports
        #
        c_port_comparison = (t_comparison + t_port).setName('c_port_comparison').setDebug(DEBUG)
        c_port_object = (k_object + t_object_name).setName('c_port_object').setDebug(DEBUG)
        c_port_range = (k_range + t_port + t_port).setName('c_port_range').setDebug(DEBUG)

        # Source and Destination Ports
        #
        c_source_port = pp.MatchFirst([c_port_comparison, c_port_object, c_port_range]).setName('c_source_port').setDebug(DEBUG)
        c_destination_port = pp.MatchFirst([c_port_comparison, c_port_object, c_port_range]).setName('c_destination_port').setParseAction(self.destination_port).setDebug(DEBUG)



        # Logging
        #
        c_logging = (k_log + pp.Optional(t_loglevel) + pp.MatchFirst([pp.Optional(k_interval + t_loginterval) , k_disable , k_default])).setName('c_logging').setDebug(DEBUG)

        # Activation
        #
        c_activation = pp.MatchFirst([k_inactive , (k_time_range + t_time_range_name)]).setName('c_activation').setDebug(DEBUG)
        c_inactive = (l_open_bracket + k_inactive + l_close_bracket).setName('c_inactive').setDebug(DEBUG)
        #pp.MatchFirst([k_inactive , (k_time_range + t_time_range_name)]).setName('c_activation').setDebug(DEBUG)

        # Hit count
        #
        c_hitcnt = l_open_bracket + k_hitcnt + l_equal + t_hitcnt_count + l_close_bracket


        # Parser
        #
        self.parser = k_access_list + \
                      t_access_list_name.setResultsName('name') + \
                      c_line + \
                      t_access_list_type.setResultsName('type') + \
                      t_action.setResultsName('action') + \
                      c_proto.setParseAction(self.protocol).setResultsName('protocol') + \
                      c_source.setParseAction(self.source).setResultsName('source') + \
                      pp.Optional(c_source_port.setParseAction(self.source_port).setResultsName('source_port')) + \
                      pp.Optional(c_destination.setResultsName('destination')) + \
                      pp.Optional(c_destination_port.setResultsName('destination_port')) + \
                      pp.Optional(c_logging.setResultsName('logging')) + \
                      pp.Optional(c_activation.setResultsName('activation')) + \
                      pp.Optional(c_hitcnt) + \
                      pp.Optional(c_inactive).setResultsName('inactive') + \
                      t_hash.setResultsName('hash')

    def parse(self, fp):

        data = []

        for line in fp:
            line = line.rstrip()

            # TODO: Add these to the parser
            # Skip some lines 
            if not line:
                # Empty lines.
                continue
            elif ';' in line:
                # access-list Other-RP-Groups; 2 elements; name hash: 0x937d0a07
                continue
            elif 'object-group' in line:
                # object groups appear expanded
                continue
            elif 'remark' in line:
                # Don't bother about remarks
                # access-list acl-in-fms line 34 remark HTTP Access to Transurban PC for view of TU LUMS
                continue
            elif 'standard' in line:
                # Later
                continue

            try:
                m = self.parser.parseString(line)
                print(line)
                print(m.asDict())
                data.append(m.asDict())
            except Exception:
                print(line, file=sys.stderr)
                raise

        return data


class Parser(BaseParser):

    def linenumber(self, tokens):
        return int(tokens[0])

    def hitcnt(self, tokens):
        return int(tokens[0])

    def protocol(self, tokens):
        return ' '.join(tokens)

    def source(self, tokens):
        return ' '.join(tokens)

    def destination(self, tokens):
        return ' '.join(tokens)


class IpAddressParser(Parser):
    """Parser converts source and destination addresses into objects.

       All returned address objects support the same operators to make
       it easier to filter the results later:

         x == y
         x != y
         x < y
         x <= y
         x > y
         x >= y
         x in y

    """

    class IPv4Range(object):
        def __init__(self, start, end):
            self.start = ipaddress.ip_address(start)
            self.end = ipaddress.ip_address(end)

        def __repr__(self):
            return "IPv4Range('{}-{}')".format(self.start, self.end)


    class Object(str):
        def __init__(self, name):
            super().__init__(name)


    class IPv4Network(ipaddress.IPv4Network):
        def __init__(self, network, netmask):
            super().__init__((network, netmask))


    class IPv4Address(ipaddress.IPv4Address):
        def __init__(self, address):
            super().__init__(address)

#            if tokens[0] == 'host':
#                self.address = ipaddress.ip_network(tokens[1])
#                self.end = None
#            elif tokens[0] == 'range':
#                self.address = ipaddress.ip_network(tokens[1])
#                self.end = ipaddress.ip_address(tokens[2])
#            elif tokens[0] == 'any':
#                self.address = ipaddress.ip_network('0.0.0.0/0')
#                self.end = None
#            elif tokens[0] == 'any4':
#                self.address = ipaddress.ip_network('0.0.0.0/0')
#                self.end = None
#            elif tokens[0] == 'object':
#                self.address = tokens[1]
#            else:
#                self.address = ipaddress.ip_network('{}/{}'.format(tokens[0], tokens[1]))
#                self.end = None
#
#        def __repr__(self):
#            if self.end:
#                return '{}-{}'.format(self.address, self.end)
#            else:
#                return '{}'.format(self.address)
#
#        def __eq__(self, other):
#            if self.end:
#                return False
#            else:
#                return self.address == ipaddress.ip_network(other)
#
#        def __lt__(self, other):
#            if self.end:
#                return self.end < ipaddress.ip_network(other)
#            else:
#                return self.address < ipaddress.ip_network(other)
#
#        def __le__(self, other):
#            if self.end:
#                return self.end <= ipaddress.ip_network(other)
#            else:
#                return self.address <= ipaddress.ip_network(other)
#
#        def __gt__(self, other):
#            return self.address > ipaddress.ip_network(other)
#
#        def __ge__(self, other):
#            return self.address >= ipaddress.ip_network(other)
#
#        def __contains__(self, other):
#            if self.end:
#                return self.start <= ipaddress.ip_network(other) <= self.end
#            else:
#                return ipaddress.ip_network(other) in self.address

    def source(self, tokens):
        if tokens[0] == 'range':
            return self.IPv4Range(start=tokens[1], end=tokens[2])
        elif tokens[0] == 'object':
            return self.Object(name=tokens[1])
        elif tokens[0] == 'host':
            return self.IPv4Address(address=tokens[1])
        elif tokens[0] == 'any' or tokens[0] == 'any4':
            return self.IPv4Network(network='0.0.0.0', netmask='0.0.0.0')
        else:
            return self.IPv4Network(network=tokens[1], netmask=tokens[2])

    destination = source
#        return source(tokens)


class PortParser(Parser):
    """Parser that converts source and destination ports into objects."""

    class Port(object):
        def __init__(self, tokens):
            pass




def main():
    # TODO: Command line arguments: input file and output format (pprint, json, yaml)

    parser = IpAddressParser()

    with open(sys.argv[1], 'rt') as fp:
        data = parser.parse(fp)

if __name__ == '__main__':
    main()
        
