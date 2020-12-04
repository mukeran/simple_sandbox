import logging
import os
import json
import re

from filters.meta import BaseFilter
from engines.meta import Engine
from .sandbox import ContainerSandbox
from .cfg.predictor import Predictor

class BinaryFilter(BaseFilter):
  def __init__(self):
    with open(os.path.join('./filters/datasets', 'binary.json'), 'r') as f:
      tmp = json.load(f)
      self.patterns = tmp["patterns"]
    for p in self.patterns:
      p['pattern'] = re.compile(p['pattern'].encode())
    ContainerSandbox.init()
    self.predictor = Predictor('./filters/binary/cfg/model/model.joblib')

  @staticmethod
  def is_elf_file(path: str):
    f = open(path, 'rb')
    elf_magic = f.read(4)
    f.close()
    if elf_magic[0] != 127 or elf_magic[1] != 69 or elf_magic[2] != 76 or elf_magic[3] != 70:
      return False
    return True

  def judge(self, type: Engine, data: dict):
    if type == Engine.HTTP:
      path = data['path']
      body = data['body']
      # check path
      for p in self.patterns:
        pattern: re.Pattern = p["pattern"]
        if pattern.findall(path):
          self.report(path, 'query')
        if pattern.findall(body):
          self.report(body, 'body')
    else:
      path: str = data['path']
      if BinaryFilter.is_elf_file(path):
        logging.info('Precheck binary ELF file {} with model'.format(path))
        result = self.predictor.is_malicious(path)
        logging.info('Result: {}, {}'.format(result, 'not secure' if result else 'secure'))
        if result:
          result = ContainerSandbox.check(path)
          if result:
            self.report(result, path)
