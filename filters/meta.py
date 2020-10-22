import abc
import json
import os.path
import logging


class BaseFilter(metaclass=abc.ABCMeta):
    def __init__(self, filename: str):
        with open(os.path.join("./filters", filename), "r")as f:
            tmp = json.load(f)
            self.patterns = tmp["patterns"]

    @abc.abstractmethod
    def judge(self, path, payload):
        pass

    @staticmethod
    def report(payload: bytes, where: str):
        s = 'Vuln found in {}, the payload is {}'.format(where, payload)
        logging.warning(s)
