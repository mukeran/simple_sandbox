import threading
import logging
import decoder as d
from scapy.all import sniff
from scapy.layers.http import HTTPRequest

from filters.meta import BaseFilter
from engines.meta import Engine

class HTTPSniffer:
  
  record: map

  def __init__(self, iface="eth0"):
    self.iface = iface
    self.filters = []
    self.decoders = []

  def start(self):
    self.t = threading.Thread(
      target=sniff,
      kwargs={"iface": self.iface, "prn": self.parse, "filter": "tcp"}
    )
    self.t.start()
  
  def join(self):
    self.t.join()

  def parse(self, pkt):
    pass
