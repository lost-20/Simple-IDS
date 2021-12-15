from scapy.all import *
from ipaddress import *


def string_IP(ip):
    string = "[Заголовок IP-пакета]" + "\n"
    string += "\t Version: " + str(ip.version) + "\n"
    string += "\t Header Length: " + str(ip.ihl * 4) + " bytes" + "\n"
    string += "\t Service Type: " + str(ip.tos) + "\n"
    string += "\t Total Length: " + str(ip.len) + "\n"
    string += "\t Identification: " + str(ip.id) + "\n"
    string += "\t Flags: " + str(ip.flags) + "\n"
    string += "\t Fragment Offset: " + str(ip.frag) + "\n"
    string += "\t Time to Live: " + str(ip.ttl) + "\n"
    string += "\t Protocol: " + str(ip.proto) + "\n"
    string += "\t Checksum: " + str(ip.chksum) + "\n"
    string += "\t Source Address: " + str(ip.src) + "\n"
    string += "\t Destination Address: " + str(ip.dst) + "\n"
    return string


def string_TCP(tcp):
    string = "[Заголовок TCP]" + "\n"
    string += "\t Source Port: " + str(tcp.sport) + "\n"
    string += "\t Destination Port: " + str(tcp.dport) + "\n"
    string += "\t Sequence Number: " + str(tcp.seq) + "\n"
    string += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
    string += "\t Data Offset: " + str(tcp.dataofs) + "\n"
    string += "\t Reserved: " + str(tcp.reserved) + "\n"
    string += "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
    string += "\t Window: " + str(tcp.window) + "\n"
    string += "\t Checksum: " + str(tcp.chksum) + "\n"
    if tcp.flags & 0x203:
        string += "\t Urgent Pointer: " + str(tcp.window) + "\n"
    return string


def string_UDP(udp):
    string = "[Заголовок UDP]" + "\n"
    string += "\t Source Port: " + str(udp.sport) + "\n"
    string += "\t Destination Port: " + str(udp.dport) + "\n"
    string += "\t Length: " + str(udp.len) + "\n"
    string += "\t Checksum: " + str(udp.chksum) + "\n"
    return string


def string_packet(pkt):
    string = ""
    if IP in pkt:
        string += string_IP(pkt[IP])
    if TCP in pkt:
        string += string_TCP(pkt[TCP])
    if UDP in pkt:
        string += string_UDP(pkt[UDP])
    return string
