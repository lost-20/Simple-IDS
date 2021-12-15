from threading import Thread
from Rules_Reader import *
from scapy.all import *
import logging
from psutil import process_iter
from signal import SIGTERM


class Sniffer(Thread):

    def __init__(self, rules):
        Thread.__init__(self)
        self.stopped = False
        self.rules = rules

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        for rule in self.rules:
            matched = rule.match(pkt)
            if matched:
                logging.warning("\n" + rule.print_message(pkt))
                action = rule.action
                if action == 2:
                    for proc in process_iter():
                        for conns in proc.connections(kind='inet'):
                            if conns.laddr.port == rule.dstPort:
                                proc.send_signal(SIGTERM)

    def run(self):
        print("Запуск Сниффера")
        sniff(prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)


