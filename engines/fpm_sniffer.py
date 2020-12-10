from engines.meta import Engine
import logging
from decoder import FastCGI
import threading
import os
import requests
from enum import Enum
import json
from scapy.all import sniff, TCP
import docker
import base64

from decoder import FastCGIDecoder
from filters import WebshellPrechecker

PROXY_URL = 'http://127.0.0.1:9001'

class InvalidUnixSocketException(Exception):
  def __init__(self, args):
    super().__init__(args)

class FPMSnifferMode(Enum):
  TCP = 0
  Unix = 1

class FPMSniffer:
  '''FPM 流量捕获器'''
  def __init__(self, mode=FPMSnifferMode.TCP, **kwargs):
    self.mode = mode
    if mode == FPMSnifferMode.TCP:
      self.iface = kwargs['iface'] if 'iface' in kwargs else 'lo'
      self.port = kwargs['port'] if 'port' in kwargs else 9000
    else:
      self.sock = kwargs['sock'] if 'sock' in kwargs else '/run/php/php7.2-fpm.sock'
      self.port = kwargs['port'] if 'port' in kwargs else 9002
      if not os.path.exists(self.sock):
        raise InvalidUnixSocketException
    self.client = docker.from_env()
    self.image = self.client.images.build(path=os.path.join(os.getcwd(), 'external/php_fpm_sandbox')) # 构建 PHP-FPM 沙箱 docker 镜像
    logging.info('PHP-FPM sandbox image built. ID: {}'.format(self.image[0].id))
    self.filter = WebshellPrechecker()

  def start(self):
    container = self.client.containers.run(self.image[0].id, ports={
      '9001/tcp': ('127.0.0.1', '9001')
    }, detach=True) # 启动 PHP-FPM 沙箱容器
    logging.info('PHP-FPM sandbox container started. ID: {}'.format(container.id))
    if self.mode == FPMSnifferMode.Unix: # 对 Unix socket 类型连接做重定向处理
      self.originalSock = self.sock + '.original'
      os.system('mv {} {}'.format(self.sock, self.originalSock))
      os.system('socat TCP-LISTEN:{},reuseaddr,fork UNIX-CONNECT:{}'.format(self.port, self.originalSock))
      os.system('socat UNIX-LISTEN:{},fork TCP-CONNECT:127.0.0.1:{}'.format(self.sock, self.port))
    self.t = threading.Thread(
      target=sniff,
      kwargs={ "iface": self.iface, "prn": self.parse, "filter": "tcp and port {}".format(self.port) }
    )
    self.t.start()

  def join(self):
    self.t.join()

  def parse(self, pkt):
    '''scapy sniff 回调函数'''
    payload = bytes(pkt[TCP].payload)
    if len(payload) == 0:
      return
    packets = FastCGIDecoder.decode(payload)
    if packets[0]['type'] == FastCGI._fcgi_request_type.FCGI_BEGIN_REQUEST: # 请求开始
      params = {}
      stdin = b''
      for packet in packets:
        if packet['type'] == FastCGI._fcgi_request_type.FCGI_PARAMS: # 合并参数 dict
          params.update(packet['params'])
        elif packet['type'] == FastCGI._fcgi_request_type.FCGI_STDIN: # 合并 stdin
          stdin += packet['content']
      if len(params) != 0:
        if not self.filter.judge(params['SCRIPT_FILENAME']): # 机器学习模型预检测
          r = requests.post(PROXY_URL, data={
            'params': json.dumps(params),
            'stdin': stdin
          }, files={
            'script': open(params['SCRIPT_FILENAME'], 'rb')
          }) # 向沙箱 Proxy 发起请求
          result = r.json()
          if result['detected']:
            logging.info('Detected PHP Execution in file {}, info: {}'.format(params['SCRIPT_FILENAME'], base64.b64decode(result['info'].encode())))
