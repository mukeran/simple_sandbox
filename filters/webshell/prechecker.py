import logging
import os

from filters.meta import BaseFilter
from engines.meta import Engine
from .php.predict import Predictor

class WebshellPrechecker(BaseFilter):
  def __init__(self):
      self.predictor = Predictor('./filters/webshell/php/model/model.joblib')

  def judge(self, path: str):
    logging.info('Prechecking PHP script file {} with model'.format(path))
    result = bool(self.predictor.predict(path))
    logging.info('Result: {}, {}'.format(result, 'not secure' if not result else 'secure'))
    return result
