import logging

from filters.meta import BaseFilter
from engines.meta import Engine
from .sandbox import ContainerSandbox
from .cfg.predictor import Predictor

class BinaryFilter(BaseFilter):
  def __init__(self):
    ContainerSandbox.init()
    self.predictor = Predictor('./filters/binary/cfg/model/model.joblib')

  @staticmethod
  def is_elf_file(path: str):
    f = open(path, 'rb')
    elf_magic = f.read(4)
    f.close()
    if len(elf_magic) < 4 or elf_magic[0] != 127 or elf_magic[1] != 69 or elf_magic[2] != 76 or elf_magic[3] != 70:
      return False
    return True

  def judge(self, type: Engine, data: dict):
    if type == Engine.FILE:
      path: str = data['path']
      if BinaryFilter.is_elf_file(path): # 判断是否为 ELF 文件
        logging.info('Precheck binary ELF file {} with model'.format(path))
        result = self.predictor.is_malicious(path) # 用机器学习模型预测是否需要用沙箱检测
        logging.info('Result: {}, {}'.format(result, 'not secure' if result else 'secure'))
        if result:
          result = ContainerSandbox.check(path) # 使用沙箱检测
          if result:
            self.report(result, path)
