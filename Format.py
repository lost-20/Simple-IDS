from ipaddress import *
from scapy.all import *


def get_IP(string):
    if string == 'any':
        return ip_network(u'0.0.0.0/0')
    else:
        string = string.split("/")
        if len(string) > 2:
            return ip_network(string[0] + '/' + string[1])
        else:
            return ip_network(string[0] + '/32')


def get_port(string):
    if string == 'any':
        string = []
        for x in range(0, 65536):
            string.append(x)
        return string

    elif ':' in string:
        string = string.split(':')
        output = []
        for x in range(int(string[0]), int(string[1]) + 1):
            output.append(x)
        return output

    elif ',' in string:
        string = string.split(',')
        string = [int(x) for x in string]
        return string

    else:
        return string