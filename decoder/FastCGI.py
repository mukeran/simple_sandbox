from enum import IntEnum

class _fcgi_request_type(IntEnum):
  '''FastCGI 请求类型'''
  FCGI_BEGIN_REQUEST = 1
  FCGI_ABORT_REQUEST = 2
  FCGI_END_REQUEST = 3
  FCGI_PARAMS = 4
  FCGI_STDIN = 5
  FCGI_STDOUT = 6
  FCGI_STDERR = 7
  FCGI_DATA = 8
  FCGI_GET_VALUES = 9
  FCGI_GET_VALUES_RESULT = 10

class FastCGIDecoder:
  '''FastCGI 解码器'''
  @staticmethod
  def __decodeHeader(raw):
    '''解码 FastCGI 包头部'''
    header = dict()
    header['version'] = raw[0]
    header['type'] = raw[1]
    header['requestId'] = (raw[2] << 8) + raw[3]
    header['contentLength'] = (raw[4] << 8) + raw[5]
    header['paddingLength'] = raw[6]
    header['reserved'] = raw[7]
    return header
  
  @staticmethod
  def __decodeParams(raw):
    '''解码 FastCGI 包参数'''
    params = {}
    while len(raw) != 0:
      keyLength = raw[0]
      if keyLength >= 0x80:
        keyLength = ((raw[0] ^ 0x80) << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
        raw = raw[4:]
      else:
        raw = raw[1:]
      valueLength = raw[0]
      if valueLength >= 0x80:
        valueLength = ((raw[0] ^ 0x80) << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
        raw = raw[4:]
      else:
        raw = raw[1:]
      key = raw[:keyLength].decode()
      value = raw[keyLength:keyLength+valueLength].decode()
      raw = raw[keyLength+valueLength:]
      params[key] = value
    return params
      

  @staticmethod
  def decode(raw):
    '''解码 FastCGI 包'''
    packets = []
    while len(raw) != 0:
      packet = FastCGIDecoder.__decodeHeader(raw)
      raw = raw[8:]
      contentLength = packet['contentLength']
      packet['content'] = raw[:contentLength]
      raw = raw[contentLength:]
      paddingLength = packet['paddingLength']
      raw = raw[paddingLength:]
      packets.append(packet)
      if packet['type'] == _fcgi_request_type.FCGI_PARAMS:
        packet['params'] = FastCGIDecoder.__decodeParams(packet['content'])
    return packets
