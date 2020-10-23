from typing import Optional
from urllib.parse import ParseResultBytes

from scapy.all import sniff
from scapy.layers.http import HTTPRequest, HTTPResponse
import filters
import threading
import logging
import decoder as d


class HTTPSniffer:
  def __init__(self, iface="eth0"):
    self.iface = iface
    self.filters = []
    self.decoders = []

  def start(self):
    t = threading.Thread(
      target=sniff,
      kwargs={"iface": self.iface, "prn": self.parse, "filter": "tcp"}
    )
    t.start()
    t.join()

  def register_filter(self, payload_filter: filters.BaseFilter):
    """
    用于注册一个过滤器

    :param payload_filter: 过滤器的父类
    :return: None
    """
    self.filters.append(payload_filter)
    logging.debug(str(payload_filter) + "注册成功")

  def register_decoder(self, decoder: d.MetaDecoder):
    """
    用于注册一个解码器

    :param decoder: 解码器的父类
    :return: None
    """
    self.decoders.append(decoder)

  def parse(self, pkt):
    if not pkt.haslayer(HTTPRequest):
      return
    content = pkt.getlayer(HTTPRequest)
    raw_path = content.Path
    raw_payload = bytes(content.payload)
    # print(raw_payload)
    path = self.recurse_decode(raw_path)
    payload = self.recurse_decode(raw_payload)
    for f in self.filters:
      f: filters.BaseFilter
      f.judge(path, payload)

  # noinspection PyBroadException
  def recurse_decode(self, data: bytes):
    """
    递归解码

    :param data:
    :return: bytes
    """
    for dcd in self.decoders:
      dcd: d.MetaDecoder
      try:
        decode_data: bytes = dcd.decode(data)
      except Exception as e:
        continue
      return self.recurse_decode(decode_data)
    return data
