import abc
import json
import os.path
import logging


class BaseFilter(metaclass=abc.ABCMeta):
  @abc.abstractmethod
  def judge(self, type, data):
    pass

  @staticmethod
  def report(payload: bytes, where: str):
    s = 'Vuln found in {}, the payload is {}'.format(where, payload)
    logging.warning(s)
