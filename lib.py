#!/usr/bin/env python
from ipaddress import *
from random import randint
import pygraphviz as pgv
from hashlib import md5
import os

# Cisco port to names mapping dictionary
portNames = {
    'aol': 5190, 'bgp': 179, 'biff': 512, 'bootpc': 68, 'bootps': 67, 'chargen': 19, 'citrix-ica': 1494, 'cmd': 514,
    'ctiqbe': 2748, 'daytime': 13, 'discard': 9, 'domain': 53, 'dnsix': 195, 'echo': 7, 'exec': 512, 'finger': 79,
    'ftp': 21, 'ftp-data': 20, 'gopher': 70, 'https': 443, 'h323': 1720, 'hostname': 101, 'ident': 113, 'imap4': 143,
    'irc': 194, 'isakmp': 500, 'kerberos': 750, 'klogin': 543, 'kshell': 544, 'ldap': 389, 'ldaps': 636, 'lpd': 515,
    'login': 513, 'lotusnotes': 1352, 'mobile-ip': 434, 'nameserver': 42, 'netbios-ns': 137, 'netbios-dgm': 138,
    'netbios-ssn': 139, 'nntp': 119, 'ntp': 123, 'pcanywhere-status': 5632, 'pcanywhere-data': 5631, 'pim-auto-rp': 496,
    'pop2': 109, 'pop3': 110, 'pptp': 1723, 'radius': 1645, 'radius-acct': 1646, 'rip': 520, 'secureid-udp': 5510,
    'smtp': 25, 'snmp': 161, 'snmptrap': 162, 'sqlnet': 1521, 'ssh': 22, 'sunrpc': 111, 'rpc': 111, 'syslog': 514,
    'tacacs': 49, 'talk': 517, 'telnet': 23, 'tftp': 69, 'time': 37, 'uucp': 540, 'who': 513, 'whois': 43, 'www': 80,
    'xdmcp': 177
}

# Make switched dict for translating from port num to name
portNumbers = {number: name for name, number in portNames.iteritems()}


# function to switch mask from 0.0.255.255 to 255.255.0.0
def switch_mask(mask):
    """
    >>> switch_mask('0.0.0.0')
    '255.255.255.255'
    >>> switch_mask('0.0.255.255')
    '255.255.0.0'
    >>> switch_mask('0.0.8.255')
    '255.255.247.0'
    >>> switch_mask('0.0.0.255')
    '255.255.255.0'
    """
    return '.'.join([str(255 - int(part)) for part in mask.split('.')])


# function for generate human readable list of ports
def ports_for_humans(ports):
    """"
    >>> ports_for_humans([22, 20, 'test', 8080])
    'ssh, ftp-data, test, 8080'
    >>> ports_for_humans([80, 443, 1000, 21])
    'www, https, 1000, ftp'
    """
    if len(ports) == 0:
        return 'all'
    else:
        # Empty arr for result
        result = []
        # for every port, try to translate it to name
        for port in ports:
            if port in portNumbers:
                result.append(portNumbers[port])
            else:
                result.append(port)

        return ', '.join([str(part) for part in result])


# Rule object class for one rule in ACL
class Rule:
    """
    >>> r1 = Rule("permit tcp any host 10.10.10.10 eq 80 443")
    >>> print r1
    permit tcp any host 10.10.10.10 eq 80 443
    >>> r1.type
    'permit'
    >>> r1.protocol
    'tcp'
    >>> r1.srcIP
    IPv4Network('0.0.0.0/0')
    >>> r1.dstIP
    IPv4Address('10.10.10.10')
    >>> r1.dstPort
    [80, 443]
    >>> r1.srcPort
    []
    >>> r2 = Rule("permit tcp host 10.1.1.1 eq 8000 8080 10.10.10.0 0.0.0.255 range 1000 1010")
    >>> print r2
    permit tcp host 10.1.1.1 eq 8000 8080 10.10.10.0 0.0.0.255 range 1000 1010
    >>> r2.protocol
    'tcp'
    >>> r2.type
    'permit'
    >>> r2.srcIP
    IPv4Address('10.1.1.1')
    >>> r2.dstIP
    IPv4Network('10.10.10.0/24')
    >>> r2.dstPort
    [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009]
    >>> r2.srcPort
    [8000, 8080]
    """
    def __init__(self, line):
        # txt representation of rule
        self.txt = line

        # parts of line
        parts = self.txt.split(' ')

        # rule type - load and del from parts
        self.type = parts[0]
        del parts[0]

        # rule protocol
        self.protocol = parts[0]
        del parts[0]

        # src IP address, src network or any
        if parts[0] == 'host':
            self.srcIP = ip_address(unicode(parts[1]))
            del parts[0:2]
        elif parts[0] == 'any':
            # set whole ips network
            self.srcIP = ip_network(u'0.0.0.0/0')
            del parts[0]
        else:
            # set source as network
            self.srcIP = ip_network(unicode(parts[0] + '/' + switch_mask(parts[1])))
            del parts[0:2]

        # if we have srcPort definition
        self.srcPort = []
        if parts[0] == 'eq':
            del parts[0]
            for port in parts:
                if port.isdigit():
                    self.srcPort.append(int(port))
                elif port in portNames:
                    self.srcPort.append(portNames[port])
                else:
                    break
            del parts[0:len(self.srcPort)]
        elif parts[0] == 'range':
            self.srcPort = range(int(parts[1]), int(parts[2]))
            del parts[0:3]

        # same for destination address
        if parts[0] == 'host':
            self.dstIP = ip_address(unicode(parts[1]))
            del parts[0:2]
        elif parts[0] == 'any':
            # set whole ips network
            self.dstIP = ip_network(u'0.0.0.0/0')
            del parts[0]
        else:
            # set source as network
            self.dstIP = ip_network(unicode(parts[0] + '/' + switch_mask(parts[1])))
            del parts[0:2]

        # if we have more parts, continue
        self.dstPort = []
        if len(parts) > 0:
            # if we have dstPort definition
            if parts[0] == 'eq':
                del parts[0]
                for port in parts:
                    if port.isdigit():
                        self.dstPort.append(int(port))
                    elif port in portNames:
                        self.dstPort.append(portNames[port])
                    else:
                        break
                del parts[0:len(self.dstPort)]
            elif parts[0] == 'range':
                self.dstPort = range(int(parts[1]), int(parts[2]))
                del parts[0:3]

    def __str__(self):
        return self.txt


# Class for representing whole ACL with rules
class ACL:
    """
    >>> acl = ACL('''ip access-list extended NC-ven
    ...  permit tcp 10.1.1.0 0.0.0.255 host 158.196.147.23 eq 28518
    ...  permit ip 10.1.1.0 0.0.0.255 host 158.196.147.23
    ...  permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888
    ...  permit udp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888
    ...  permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 8888
    ...  permit icmp 10.1.1.0 0.0.0.255 host 158.196.141.88 echo
    ...  permit tcp 10.1.1.0 0.0.0.255 host 193.62.193.80 eq www
    ...  permit tcp 10.1.1.0 0.0.0.255 host 193.144.127.203 eq www
    ...  deny   ip 10.1.1.0 0.0.0.255 any''')
    >>> acl.txt
    'ip access-list extended NC-ven\\n permit tcp 10.1.1.0 0.0.0.255 host 158.196.147.23 eq 28518\\n permit ip 10.1.1.0 0.0.0.255 host 158.196.147.23\\n permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888\\n permit udp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888\\n permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 8888\\n permit icmp 10.1.1.0 0.0.0.255 host 158.196.141.88 echo\\n permit tcp 10.1.1.0 0.0.0.255 host 193.62.193.80 eq www\\n permit tcp 10.1.1.0 0.0.0.255 host 193.144.127.203 eq www\\n deny   ip 10.1.1.0 0.0.0.255 any'
    >>> acl.lines
    ['ip access-list extended NC-ven', 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.147.23 eq 28518', 'permit ip 10.1.1.0 0.0.0.255 host 158.196.147.23', 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', 'permit udp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 8888', 'permit icmp 10.1.1.0 0.0.0.255 host 158.196.141.88 echo', 'permit tcp 10.1.1.0 0.0.0.255 host 193.62.193.80 eq www', 'permit tcp 10.1.1.0 0.0.0.255 host 193.144.127.203 eq www', 'deny ip 10.1.1.0 0.0.0.255 any']
    >>> packet1 = Packet(protocol='udp', src_ip='10.10.10.10', src_port='', dst_ip='10.10.10.1', dst_port='80')
    >>> acl.check_packet(packet1)
    [[False, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.147.23 eq 28518', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch', 'destination port mismatch']], [False, 'permit ip 10.1.1.0 0.0.0.255 host 158.196.147.23', ['source IP mismatch', 'destination IP mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch', 'destination port mismatch']], [False, 'permit udp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', ['source IP mismatch', 'destination IP mismatch', 'destination port mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 8888', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch', 'destination port mismatch']], [False, 'permit icmp 10.1.1.0 0.0.0.255 host 158.196.141.88 echo', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 193.62.193.80 eq www', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 193.144.127.203 eq www', ['protocol mismatch', 'source IP mismatch', 'destination IP mismatch']], [False, 'deny ip 10.1.1.0 0.0.0.255 any', ['source IP mismatch']]]
    >>> packet2 = Packet(protocol='tcp', src_ip='10.1.1.1', src_port='', dst_ip='158.196.147.23', dst_port='28518')
    >>> acl.check_packet(packet2)
    [[True, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.147.23 eq 28518', []], [True, 'permit ip 10.1.1.0 0.0.0.255 host 158.196.147.23', []], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', ['destination IP mismatch', 'destination port mismatch']], [False, 'permit udp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 18888', ['protocol mismatch', 'destination IP mismatch', 'destination port mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 158.196.141.88 eq 8888', ['destination IP mismatch', 'destination port mismatch']], [False, 'permit icmp 10.1.1.0 0.0.0.255 host 158.196.141.88 echo', ['protocol mismatch', 'destination IP mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 193.62.193.80 eq www', ['destination IP mismatch', 'destination port mismatch']], [False, 'permit tcp 10.1.1.0 0.0.0.255 host 193.144.127.203 eq www', ['destination IP mismatch', 'destination port mismatch']], [True, 'deny ip 10.1.1.0 0.0.0.255 any', []]]
    >>> acl.generate_graph() # doctest: +ELLIPSIS
    '....png'
    """
    def __init__(self, txt):
        # storing txt input
        self.txt = txt

        # Preparing text lines
        self.lines = []
        for line in self.txt.split('\n'):
            self.lines.append(' '.join(line.split()))

        self.rules = []

        # For every line in ACL
        for num, line in enumerate(self.lines):
            # Strip lines
            line = line.strip()

            # If line is ACL definition, continue
            if line.startswith('ip access-list') or line.startswith('Extended IP access list'):
                continue

            # If line starts with digit (copied from console), continue without numbers
            if line.split(' ')[0].isdigit():
                line = ' '.join(line.split(' ')[1:]).strip()

            # If line ends with count of matches (also from CLI), remove this information (2 parts)
            if line.endswith('matches)'):
                line = ' '.join(line.split(' ')[:-2]).strip()

            # Also remove established tag - we can't handle with it
            if line.endswith('established'):
                line = ' '.join(line.split(' ')[:-1]).strip()

            try:
                self.rules.append(Rule(line))
            except Exception as e:
                raise RuntimeError('Error parsing rule on line %d\nRule: %s\nError message:%s' % (num, line, e))

    def check_packet(self, packet):
        result = []
        for rule in self.rules:
            reasons = []
            # Check protocol
            if not (packet.protocol == rule.protocol or rule.protocol == 'ip'):
                reasons.append('protocol mismatch')

            # Check source
            if not ((isinstance(rule.srcIP, IPv4Address) and rule.srcIP == packet.srcIP)
                    or (isinstance(rule.srcIP, IPv4Network) and packet.srcIP in rule.srcIP)):
                reasons.append('source IP mismatch')

            # source port
            if not (len(rule.srcPort) == 0 or packet.srcPort in rule.srcPort):
                reasons.append('sorce port mismatch')

            # Check destination
            if not ((isinstance(rule.dstIP, IPv4Address) and rule.dstIP == packet.dstIP)
                    or (isinstance(rule.dstIP, IPv4Network) and packet.dstIP in rule.dstIP)):
                reasons.append('destination IP mismatch')

            # destination port
            if not (len(rule.dstPort) == 0 or packet.dstPort in rule.dstPort):
                reasons.append('destination port mismatch')

            if len(reasons) > 0:
                status = False
            else:
                status = True

            result.append([status, rule.txt, reasons])

        return result

    def generate_graph(self):
        # make graphname as hash from ACL content
        graphname = md5(self.txt).hexdigest() + '.png'

        graphfolder = os.path.abspath(os.path.dirname(__file__)) + '/graphs/'

        # if graph for same ACL exists, return its name
        if os.path.exists(graphfolder + graphname):
            return graphname
        else:
            # create graph
            graph = pgv.AGraph(strict=False, directed=True)
            # set default shape to box
            graph.node_attr['shape'] = 'box'

            # for every rule create a edge between two nodes
            for rule in self.rules:
                # Coloring edges based on rule type
                if rule.type == 'permit':
                    color = 'green'
                else:
                    color = 'red'
                # Add edge to graph
                graph.add_edge(rule.srcIP, rule.dstIP, width='4.0', len='3.0', color=color, label='%s --> %s' % (
                    ports_for_humans(rule.srcPort), ports_for_humans(rule.dstPort)))

            # initialize layout
            graph.layout()
            # write graph to image
            graph.draw(graphfolder + graphname)
            # return graph name
            return graphname


# Class representing one packet
class Packet:
    """
    >>> packet1 = Packet(protocol='udp', src_ip='10.10.10.10', src_port='3333', dst_ip='10.10.10.1', dst_port='80')
    >>> print packet1
    udp - 10.10.10.10:3333 --> 10.10.10.1:80
    >>> packet1.srcPort
    3333
    >>> packet1.srcIP
    IPv4Address('10.10.10.10')
    >>> packet1.dstPort
    80
    >>> packet1.dstIP
    IPv4Address('10.10.10.1')
    """
    def __init__(self, protocol, src_ip, src_port, dst_ip, dst_port):
        self.protocol = protocol
        self.srcIP = ip_address(unicode(src_ip))

        # src port can be random number or name
        if src_port == '':
            self.srcPort = randint(1, 65536)
        elif not src_port.isdigit():
            self.srcPort = portNames['src_port']
        else:
            self.srcPort = int(src_port)

        self.dstIP = ip_address(unicode(dst_ip))

        # dst port can be random number or name
        if dst_port == '':
            self.dstPort = randint(1, 65536)
        elif not dst_port.isdigit():
            self.dstPort = portNames[dst_port]
        else:
            self.dstPort = int(dst_port)

    def __str__(self):
        return '%s - %s:%s --> %s:%s' % (self.protocol, self.srcIP, self.srcPort, self.dstIP, self.dstPort)
