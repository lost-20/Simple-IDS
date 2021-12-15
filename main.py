from Rules_Reader import *
from Sniffer import *
from scapy.all import *
import sys


def main(exampleRules, output):
    exampleRules = exampleRules.split("\n")
    exampleRules = exampleRules[:-1]
    global rules
    rules = []
    for line in exampleRules:
        rule = Rules(line)
        rules.append(rule)
    logging.basicConfig(filename= output, level=logging.INFO)
    sniffer = Sniffer(rules)
    sniffer.start()
