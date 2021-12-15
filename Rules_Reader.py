from Output_Format import *
from Format import *
from ipaddress import *
from scapy.all import *
import datetime

class Rules:

    def __init__(self, str):
        self.string = str

        line = str.strip()
        line = line.split(" ")

        if line[0] == 'alert':
            self.action = 1
        if line[0] == 'block':
            self.action = 2

        if line[1] == "TCP":
            self.protocol = 0
        if line[1] == "UDP":
            self.protocol = 1

        self.srcIP = get_IP(line[2])
        self.srcPort = get_port(line[3])
        self.dstIP = get_IP(line[5])
        self.dstPort = get_port(line[6])

        options = str.split('(')
        options[1] = options[1][:-2]
        options = options[1].split(';')
        for opt in options:
            opt = opt.split(":", 1)
            if opt[0] == 'msg':
                self.msg = opt[1]
            if opt[0] == 'flags':
                self.flags = opt[1]
            if opt[0] == 'len':
                self.len = int(opt[1])

    def __repr__(self):
        return self.string

    def check_Protocol(self, pkt):
        check = False
        if self.protocol == 0 and TCP in pkt:
            check = True
        elif self.protocol == 1 and UDP in pkt:
            check = True
        return check

    def check_IP(self, pkt):
        check = False

        if IP not in pkt:
            return False
        else:
            srcIP = pkt[IP].src
            dstIP = pkt[IP].dst
            ipSrc = ip_address(str(srcIP))
            ipDst = ip_address(str(dstIP))
            try:
                if ipSrc in self.srcIP and ipDst in self.dstIP:
                    check = True
            except TypeError:
                check = False
        return check

    def check_Port(self, pkt):
        check = False

        if TCP in pkt:
            srcPort = pkt[TCP].sport
            dstPort = pkt[TCP].dport
            try:
                if srcPort in self.srcPort and dstPort in self.dstPort:
                    check = True
            except TypeError:
                check = False

        elif UDP in pkt:
            srcPort = pkt[UDP].sport
            dstPort = pkt[UDP].dport
            try:
                if srcPort in self.srcPort and dstPort in self.dstPort:
                    check = True
            except TypeError:
                    check = False
        return check

    def check_Options(self, pkt):
        check = True

        if hasattr(self, 'len'):
            if IP in pkt:
                if self.len != int(pkt[IP].ihl):
                    return False
            else:
                return False

        if hasattr(self, 'flags'):
            if TCP not in pkt:
                return False
            else:
                for flag in self.flags:
                    pktFlags = pkt[TCP].underlayer.sprintf("%TCP.flags%")
                    if flag not in pktFlags:
                        return False
        return check

    def match(self, pkt):
        if not self.check_Protocol(pkt):
            return False

        if not self.check_IP(pkt):
            return False

        if not self.check_Port(pkt):
            return False

        if not self.check_Options(pkt):
            return False

        return True

    def print_message(self, pkt):
        date = datetime.datetime.now()
        msg = str(date) + '\n'

        if self.action == 1:
            msg += 'ALERT '

        if self.action == 2:
            msg += "BLOCK "

        if hasattr(self, "msg"):
            msg += self.msg + '"\n'

        msg += "Совпала сигнатура :\n" + str(self) + "\n"
        msg += "В пакете :\n" + string_packet(pkt) + "\n"

        return msg


