'''
文件已废弃
'''

import urllib.parse
import base64
import abc


def decorator(func):
  def _f(raw):
    decoded_data: bytes = func(raw)
    if decoded_data == raw:
      raise Exception
    else:
      return decoded_data

  return _f


class MetaDecoder(metaclass=abc.ABCMeta):
  @staticmethod
  @decorator
  @abc.abstractmethod
  def decode(raw: bytes):
    """
    解码

    @:rtype bytes
    """
    return b''


class UrlDecoder(MetaDecoder):

  @staticmethod
  @decorator
  def decode(raw: bytes):
    decoded_data = raw.decode()
    decoded_data = urllib.parse.unquote(decoded_data)
    decoded_data = decoded_data.encode()
    return decoded_data


class Base64Decoder(MetaDecoder):
  @staticmethod
  @decorator
  def decode(raw: bytes):
    return base64.b64decode(raw)


if __name__ == '__main__':
  data = UrlDecoder.decode(b"%27%28%29")
  try:
    data2 = UrlDecoder.decode(b'aaabbbbcccc')
  except Exception as e:
    print(e)
