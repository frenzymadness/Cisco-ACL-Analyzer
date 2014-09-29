#!/usr/bin/env python
from ipaddress import *
from random import randint


# function to switch mask from 0.0.255.255 to 255.255.0.0
def switchMask(mask):
    return '.'.join([str(255 - int(part)) for part in mask.split('.')])

# Cisco port to names mapping dictionary
portNames = {'aol': 5190, 'bgp': 179, 'biff': 512, 'bootpc': 68, 'bootps': 67, 'chargen': 19, 'citrix-ica': 1494, 'cmd': 514, 'ctiqbe': 2748, 'daytime': 13, 'discard': 9, 'domain': 53, 'dnsix': 195, 'echo': 7, 'exec': 512, 'finger': 79, 'ftp': 21, 'ftp-data': 20, 'gopher': 70, 'https': 443, 'h323': 1720, 'hostname': 101, 'ident': 113, 'imap4': 143, 'irc': 194, 'isakmp': 500, 'kerberos': 750, 'klogin': 543, 'kshell': 544, 'ldap': 389, 'ldaps': 636, 'lpd': 515, 'login': 513, 'lotusnotes': 1352, 'mobile-ip': 434, 'nameserver': 42, 'netbios-ns': 137, 'netbios-dgm': 138, 'netbios-ssn': 139, 'nntp': 119, 'ntp': 123, 'pcanywhere-status': 5632, 'pcanywhere-data': 5631, 'pim-auto-rp': 496, 'pop2': 109, 'pop3': 110, 'pptp': 1723, 'radius': 1645, 'radius-acct': 1646, 'rip': 520, 'secureid-udp': 5510, 'smtp': 25, 'snmp': 161, 'snmptrap': 162, 'sqlnet': 1521, 'ssh': 22, 'sunrpc': 111, 'rpc': 111, 'syslog': 514, 'tacacs': 49, 'talk': 517, 'telnet': 23, 'tftp': 69, 'time': 37, 'uucp': 540, 'who': 513, 'whois': 43, 'www': 80, 'xdmcp': 177}


# Rule object class for one rule in ACL
class Rule:
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
            self.srcIP = ip_network(unicode(parts[0] + '/' + switchMask(parts[1])))
            del parts[0:2]

        # if we have srcPort definition
        self.srcPort = []
        if parts[0] == 'eq':
            del parts[0]
            for port in parts:
                if port.isdigit():
                    self.srcPort.append(int(port))
                    parts.remove(port)
                elif port in portNames:
                    self.srcPort.append(portNames[port])
                    parts.remove(port)
                else:
                    break
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
            self.dstIP = ip_network(unicode(parts[0] + '/' + switchMask(parts[1])))
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
                        parts.remove(port)
                    elif port in portNames:
                        self.dstPort.append(portNames[port])
                        parts.remove(port)
                    else:
                        break
            elif parts[0] == 'range':
                self.dstPort = range(int(parts[1]), int(parts[2]))
                del parts[0:3]

    def __str__(self):
        return self.txt
        #return 'Type:%s\nProtocol:%s\nSrcIP:%s\nSrcPorts:%s\nDstIP:%s\nDstPorts:%s\n' % (self.type, self.protocol, self.srcIP, self.srcPort, self.dstIP, self.dstPort)


# Class for representing whole ACL with rules
class ACL:
    def __init__(self, lines):
        # Preparing text lines
        self.lines = []
        for line in lines:
            self.lines.append(' '.join(line.split()))

        self.rules = []

        # For every line in ACL
        for num, line in enumerate(self.lines):
            # Strip lines
            line = line.strip()

            # If line is ACL definition, continue
            if line.startswith('ip access-list'):
                continue

            # If line starts with digit (copied from console), continue without numbers
            if line.split(' ')[0].isdigit():
                line = line.split(' ')[1:]
                line = ' '.join(line).strip()
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
            if not ((isinstance(rule.srcIP, IPv4Address) and rule.srcIP == packet.srcIP) or (isinstance(rule.srcIP, IPv4Network) and packet.srcIP in rule.srcIP)):
                reasons.append('source IP mismatch')

            # source port
            if not (len(rule.srcPort) == 0 or packet.srcPort in rule.srcPort):
                reasons.append('sorce port mismatch')

            # Check destination
            if not ((isinstance(rule.dstIP, IPv4Address) and rule.dstIP == packet.dstIP) or (isinstance(rule.dstIP, IPv4Network) and packet.dstIP in rule.dstIP)):
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


# Class representing one packet
class Packet:
    def __init__(self, protocol, srcIP, srcPort, dstIP, dstPort):
        self.protocol = protocol
        self.srcIP = ip_address(unicode(srcIP))

        # src port can be random number or name
        if srcPort == '':
            self.srcPort = randint(1, 65536)
        elif not srcPort.isdigit():
            self.srcPort = portNames['srcPort']
        else:
            self.srcPort = int(srcPort)

        self.dstIP = ip_address(unicode(dstIP))

        # dst port can be random number or name
        if dstPort == '':
            self.dstPort = randint(1, 65536)
        elif not dstPort.isdigit():
            self.dstPort = portNames[dstPort]
        else:
            self.dstPort = int(dstPort)


    def __str__(self):
        return '%s - %s:%s --> %s:%s' % (self.protocol, self.srcIP, self.srcPort, self.dstIP, self.dstPort)
