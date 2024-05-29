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
import netaddr
import logging


logging.basicConfig(level=logging.DEBUG)

# Import different versions on PyParsing depending
# on the second command line argument.
try:
    import cPyparsing as pp
except ImportError:
    import pyparsing as pp
pp.ParserElement.enablePackrat()

LAYER1 = 1
LAYER2 = 2
LAYER3 = 3
LAYER4 = 4
PROTOCOLS = {
    'ip': LAYER3,
    'icmp': LAYER4,
    'udp': LAYER4,
    'tcp': LAYER4
}


# TODO:
## Names to number tables for TCP/UDP ports and protocols like (icmp, IP, TCP, UPD).
## Only names that cannot be resolved through `getservbyname()` listed here.
## https://community.cisco.com/t5/firewalls/cisco-asa-acl-built-in-port-name-to-number-mapping/td-p/1709769

class Any(object):
    """Object that matches anything."""

    def __init__(self):
        pass

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return True

    def __lt__(self, other):
        return True

    def __gt__(self, other):
        return True

    def __ge__(self, other):
        return True

    def __le__(self, other):
        return True

    def __contains__(self, other):
        return True

    def __repr__(self):
        return '{}'.format(self.__class__.__name__)


class Rule:

    def __init__(self, acl, **kwargs):
        self.acl = acl
        self.line = kwargs.get('line')
        self.type = kwargs.get('type')
        self.action = kwargs.get('action')
        self.proto = kwargs.get('proto', Any())
        self.src = kwargs.get('src', Any())
        self.dst = kwargs.get('dst', Any())
        self.sport = kwargs.get('sport', Any())
        self.dport = kwargs.get('dport', Any())
        self.hits = self.matches = kwargs.get('hits', kwargs.get('matches', 0))
        self.hash = kwargs.get('hash')
        self.remark = kwargs.get('remark')
        self.established = kwargs.get('established', False)

    def __repr__(self):
        return str({k: v for k,v in self.__dict__.items() if v is not None})

    def __hash__(self):
        return hash('{}{}{}{}{}{}'.format(self.action, self.proto, self.src, self.dst,
                                          self.sport, self.dport, self.established))

    def __eq__(self, other):
        return hash(self) == hash(other)
    
    def __contains__(self, other):
        pass

#    def __ne__(self, other):
#        return hash(self) != hash(other)

#    def __gt__(self, other):
#        return False

#    def __lt__(self, other):
#        return False

#    def __ge__(self, other):
#        return self == other

#    def __le__(self, other):
#        return self == other


class Number(int):
    def __init__(self, tokens):
        super().__init__(tokens[0])


class Action(object):
    def __init__(self, tokens):
        self.action = tokens[0]

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.action)

    def __hash__(self):
        return hash(self.action)

    def __eq__(self, other):
        return self.action == other.action
    
#    def __gt__(self, other):
#        return self.action == other.action


class Proto(object):
    def __init__(self, tokens):
        self.proto = tokens[0]

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.proto)

    def __eq__(self, other):
        return self.proto == other
    
    def __contains__(self, other):
        return other >= self
        
    def __gt__(self, other):
        return PROTOCOLS.get(self.proto) > PROTOCOLS.get(other.proto)
        
#    def __lt__(self, other):
#        return  PROTOCOLS.get(self.proto) < PROTOCOLS.get(other.proto)
        
    def __ge__(self, other):
        return  PROTOCOLS.get(self.proto) >= PROTOCOLS.get(other.proto)
        
#    def __le__(self, other):
#        return PROTOCOLS.get(self.proto) <= PROTOCOLS.get(other.proto)


class Address(object):
    def __init__(self, tokens):
        if tokens[0] == 'range':
            self.address = netaddr.IPRange(tokens[1], tokens[2])
        elif tokens[0] in ('object', 'object-group'):
            self.address = tokens[1]
        elif tokens[0] == 'host':
            self.address = netaddr.IPAddress(tokens[1])
        elif tokens[0] == 'any' or tokens[0] == 'any4':
            self.address = netaddr.IPRange('0.0.0.0', '255.255.255.255')
        elif len(tokens) == 1:
            self.address = netaddr.IPAddress(tokens[0])
        elif len(tokens) == 5 and tokens[2] == 'wildcard' and tokens[3] == 'bits':
            # ['10.49.5.0', ',', 'wildcard', 'bits', '0.0.0.255']
            self.address = netaddr.IPNetwork('{}/{}'.format(tokens[0], tokens[4]))
        else:
            self.address = netaddr.IPNetwork('{}/{}'.format(tokens[0], tokens[1]))

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.address)
    
    def __eq__(self, other):
        return self.address == other.address
    
    def __ne__(self, other):
        return self.address != other.address
    
    def __gt__(self, other):
        return self.address > other.address
    
    def __ge__(self, other):
        return self.address >= other.address
    
    def __lt__(self, other):
        return self.address < other.address
    
    def __le__(self, other):
        return self.address <= other.address
    
    def __contains__(self, other):
        return self.address in other.address
      

class Port(object):
    """Single or range of (TCP/UDP) ports."""
    def __init__(self, tokens):
        if tokens[0] == 'eq':
            self.minport = self.maxport = self.toint(tokens[1])
        elif tokens[0] == 'ge':
            self.minport = self.toint(tokens[1])
            self.maxport = 65535
        elif tokens[0] == 'gt':
            self.minport = self.toint(tokens[1])+1
            self.maxport = 65535
        elif tokens[0] == 'le':
            self.minport = 1
            self.maxport = self.toint(tokens[1])
        elif tokens[0] == 'lt':
            self.minport = 1
            self.maxport = self.toint(tokens[1])-1
        elif tokens[0] == 'range':
            self.minport = self.toint(tokens[1])
            self.maxport = self.toint(tokens[2])
        else:
            raise ValueError(str(tokens))

    def __repr__(self):
        return '{}({},{})'.format(self.__class__.__name__, 
                                  self.minport, self.maxport)

    def toint(self, x):
        try:
            return int(x)
        except ValueError:
            return socket.getservbyname(x)
#        return {'domain': 53,
#
#                }.get(i, int(i))
        
    def toport(self, p):
        if isinstance(p, Port):
            return p
        else:
            try:
                Port(['range', p[0], p[1]])
            except IndexError:
                Port(['eq', p])
                
    def __eq__(self, other):
        """Port() == 80
           Port() in (1024,1100)
        """
        
        other = self.toport(other)
        return (self.minport == other.minport and 
                self.maxport == other.maxport)
        
    def __gt__(self, other):
        other = self.toport(other)
        return self.minport > other.maxport
        
    def __ge__(self, other):
        other = self.toport(other)
        return self.minport >= other.minport
    
    def __lt__(self, other):
        other = self.toport(other)
        return self.maxport > other.minport  

    def __le__(self, other):
        other = self.toport(other)
        return self.maxport <= other.maxport
    
    def __contains__(self, other):
        other = self.toport(other)
        return (self.minport >= other.minport and 
                self.maxport <= other.maxport)
    
#class Hits(int):
#    pass
#
#class Hash(str):
#    pass
#
#class Remark(str):
#    pass


class Parser(object):

    # Remember the name/number of the ACL so it can be injected into
    # every rule.
    #
    def set_acl(self, tokens):
        self.acl = tokens[0]

    def __init__(self):
        self.acl = None


        # -------------------------------------------------
        #
        # Basic tokens
        #
        t_integer = pp.Word(pp.nums).setParseAction(lambda tokens: int(tokens[0]))
        t_string = pp.Word(pp.alphanums)


        # -------------------------------------------------
        #
        # Literals
        #
        l_close_bracket = pp.Literal(')').setName('l_close_bracket')
        l_open_bracket = pp.Literal('(').setName('l_open_bracket')
        l_dot = pp.Literal('.').setName('l_dot')
        l_equal = pp.Literal('=').setName('l_equal')
        l_comma = pp.Literal(',').setName('l_comma')


        # -------------------------------------------------
        #
        # Keywords
        #
        k_Standard = pp.Keyword('Standard')
        k_Extended = pp.Keyword('Extended')
        k_IP = pp.Keyword('IP')
        k_access = pp.Keyword('access')
        k_list = pp.Keyword('list')
        k_wildcard = pp.Keyword('wildcard')
        k_bits = pp.Keyword('bits')
        k_access_list = pp.Keyword('access-list')
        k_any4 = pp.Keyword('any4')
        k_any6 = pp.Keyword('any6')
        k_any = pp.Keyword('any')
        k_deny = pp.Keyword('deny')
        k_eq = pp.Keyword('eq')
        k_extended = pp.Keyword('extended')
        k_gt = pp.Keyword('gt')
        k_hitcnt = pp.Keyword('hitcnt')
        k_host = pp.Keyword('host')
        k_icmp = pp.Keyword('icmp')
        k_interval = pp.Keyword('k_interval')
        k_ip = pp.Keyword('ip')
        k_line = pp.Keyword('line')
        k_log = pp.Keyword('log')
        k_lt = pp.Keyword('lt')
        k_permit= pp.Keyword('permit')
        k_range = pp.Keyword('range')
        k_standard = pp.Keyword('standard')
        k_tcp = pp.Keyword('tcp')
        k_udp = pp.Keyword('udp')
        k_inactive = pp.Keyword('inactive')
        k_disable = pp.Keyword('disable')
        k_default = pp.Keyword('default')
        k_object = pp.Keyword('object')
        k_object_group = pp.Keyword('object-group')
        k_time_range = pp.Keyword('time-range')
        k_matches = pp.Keyword('matches')
        k_established = pp.Keyword('established').setResultsName('established').setParseAction(lambda tokens: True)


        # -------------------------------------------------
        #
        # Tokens
        #
        t_access_list_name = pp.Word(pp.alphanums+'-'+'_').setParseAction(self.set_acl).setResultsName('__skip__')
        t_access_list_type = pp.MatchFirst([k_standard,k_extended]).setName('t_access_list_type')
        t_action = pp.MatchFirst([k_permit,k_deny]).setResultsName('action').setParseAction(Action)
        t_comparison = pp.MatchFirst([k_eq,k_gt,k_lt]).setName('t_comparison')
        # some comparisons are missing
        t_hash = pp.Word(pp.alphanums).setName('t_hash')
        t_hitcnt_count = pp.Word(pp.nums).setName('t_hitcnt_count').setResultsName('hitcnt').setParseAction(Number)
        t_octet = pp.Word(pp.nums, max=3).setName('t_octet')
        # TODO: Use pyparsing's inbuilt IPv4 address
        t_ipaddress = pp.Combine(t_octet + l_dot + t_octet + l_dot + t_octet + l_dot + t_octet)
        t_netmask = pp.Combine(t_octet + l_dot + t_octet + l_dot + t_octet + l_dot + t_octet)
        t_line_number = pp.Word(pp.nums).setName('t_line_number').setParseAction(Number)
        t_loginterval = pp.Word(pp.nums).setName('t_loginterval')
        t_loglevel = pp.Word(pp.alphas).setName('t_loglevel')
        t_port = pp.Word(pp.alphanums + '-').setName('t_port')
        t_object_name = pp.Word(pp.alphanums + '_').setName('t_object_name')
        t_time_range_name = pp.Word(pp.alphanums).setName('t_time_range_name')


        # Line and number
        #
        c_line = k_line + t_line_number.setResultsName('line')


        # Objects and object groups
        #
        c_object = (k_object + t_object_name).setName('c_object')
        c_object_group = (k_object_group + t_object_name).setName('c_object_group')

        # Protocol
        #
        c_proto = pp.MatchFirst([k_ip , k_icmp , k_tcp , k_udp , c_object , c_object_group]).setResultsName('proto').setParseAction(Proto)

        # Addresses
        #
        c_address_host = (k_host + t_ipaddress).setName('c_address_host')
        c_address_ipv4 = (t_ipaddress + t_netmask).setName('c_address_ipv4')
        c_address_any = pp.MatchFirst([k_any , k_any4 , k_any6]).setName('c_address_any')
        c_address_range = (k_range + t_ipaddress + t_ipaddress).setName('c_address_range')
        c_address_object = (k_object + t_object_name).setName('c_address_object')
        c_address_object_group = (k_object_group + t_object_name).setName('c_address_object_group')

        # Source and Destination Address
        #
        c_source = pp.MatchFirst([c_address_host , c_address_ipv4 , c_address_any , c_address_range , c_address_object, c_address_object_group]).setResultsName('src').setParseAction(Address)
        c_destination = pp.MatchFirst([c_address_host , c_address_ipv4 , c_address_any , c_address_range , c_address_object, c_address_object_group]).setResultsName('dst').setParseAction(Address)

        # Ports
        #
        c_port_comparison = (t_comparison + t_port).setName('c_port_comparison')
        c_port_object = (k_object + t_object_name).setName('c_port_object')
        c_port_range = (k_range + t_port + t_port).setName('c_port_range')

        # Source and Destination Ports
        #
        c_source_port = pp.MatchFirst([c_port_comparison, c_port_object, c_port_range]).setResultsName('sport').setParseAction(Port)
        c_destination_port = pp.MatchFirst([c_port_comparison, c_port_object, c_port_range]).setResultsName('dport').setParseAction(Port)



        # Logging
        #
        c_logging = (k_log + pp.Optional(t_loglevel) + pp.MatchFirst([pp.Optional(k_interval + t_loginterval) , k_disable , k_default])).setName('c_logging')

        # Activation
        #
        c_activation = pp.MatchFirst([k_inactive , (k_time_range + t_time_range_name)]).setName('c_activation')
        c_inactive = (l_open_bracket + k_inactive + l_close_bracket).setName('c_inactive')
        #pp.MatchFirst([k_inactive , (k_time_range + t_time_range_name)]).setName('c_activation').setDebug(DEBUG)

        # Hit count
        #
        c_hitcnt = l_open_bracket + k_hitcnt + l_equal + t_hitcnt_count + l_close_bracket


        # -------------------------------------------------
        #
        # Line grammars
        #

        # IOS Standard IP access list <number>
        #   <number> <action> <source>, wildcard bits <wildcard> (<matches> matches)
        #
        g_standard_ip_access_list_header = k_Standard + k_IP + k_access + k_list + t_access_list_name
        g_standard_ip_access_list_rule = t_integer.setResultsName('line') + \
                                         t_action + \
                                         (t_ipaddress + pp.Optional(l_comma + k_wildcard + k_bits + t_netmask)).setResultsName('src').setParseAction(Address) + \
                                         pp.Optional(l_open_bracket + t_integer.setResultsName('matches') + k_matches + l_close_bracket)


        # IOS Extended IP access list <name>
        #
        g_extended_ip_access_list_header = k_Extended + k_IP + k_access + k_list + t_access_list_name
        g_extended_ip_access_list_rule = t_integer.setResultsName('line') + \
                                         t_action + \
                                         c_proto + \
                                         c_source  + \
                                         pp.Optional(c_source_port) + \
                                         c_destination  + \
                                         pp.Optional(c_destination_port) + \
                                         pp.Optional(k_established) + \
                                         pp.Optional(l_open_bracket + t_integer.setResultsName('matches') + k_matches + l_close_bracket)


        # -------------------------------------------------
        #
        # Parser
        #


        self.parser = g_standard_ip_access_list_header | \
                      g_extended_ip_access_list_rule | \
                      g_standard_ip_access_list_rule | \
                      g_extended_ip_access_list_header


# Fragments of the ASA parser TODO:
#        # Parser
#        #
#        self.parser = k_access_list + \
#                      t_access_list_name.setResultsName('name') + \
#                      c_line + \
#                      t_access_list_type.setResultsName('type') + \
#                      t_action.setResultsName('action') + \
#                      c_proto.setParseAction(self.protocol).setResultsName('protocol') + \
#                      c_source.setParseAction(self.source).setResultsName('source') + \
#                      pp.Optional(c_source_port.setParseAction(self.source_port).setResultsName('source_port')) + \
#                      pp.Optional(c_destination.setResultsName('destination')) + \
#                      pp.Optional(c_destination_port.setResultsName('destination_port')) + \
#                      pp.Optional(c_logging.setResultsName('logging')) + \
#                      pp.Optional(c_activation.setResultsName('activation')) + \
#                      pp.Optional(c_hitcnt) + \
#                      pp.Optional(c_inactive).setResultsName('inactive') + \
#                      t_hash.setResultsName('hash')

    def parse(self, fp):

        for line in fp:
            line = line.rstrip()

            if not line:
                continue

            # For now, terminate on MAC
            #
            if 'MAC access list' in line:
                return


            print('<<<', line)

#            # TODO: Add these to the parser
#            # Skip some lines 
#            if not line:
#                # Empty lines.
#                continue
#            elif ';' in line:
#                # access-list Other-RP-Groups; 2 elements; name hash: 0x937d0a07
#                continue
#            elif 'object-group' in line:
#                # object groups appear expanded
#                continue
#            elif 'remark' in line:
#                # Don't bother about remarks
#                # access-list acl-in-fms line 34 remark HTTP Access to Transurban PC for view of TU LUMS
#                continue
#            elif 'standard' in line:
#                # Later
#                continue

            try:
                m = self.parser.parseString(line)
                d = m.asDict()
                if '__skip__' in d:
                    continue
                else:
                    yield Rule(self.acl, **d)
            except Exception:
                raise


def parse(fp):
    parser = Parser()

    for rule in parser.parse(fp):
        yield rule


def main():
    # TODO: Command line arguments: input file and output format (pprint, json, yaml)

    with open(sys.argv[1], 'rt') as fp:
        for rule in parse(fp):
            print('>>>', rule, hash(rule))

if __name__ == '__main__':
    main()
        
