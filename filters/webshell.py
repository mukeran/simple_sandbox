import abc
import logging
import re
from filters.meta import BaseFilter


class WebshellFilter(BaseFilter):
  def __init__(self):
    BaseFilter.__init__(self, "webshell.json")
    for p in self.patterns:
      # print(p["pattern"])
      p["pattern"] = re.compile(p["pattern"].encode())

  def judge(self, path, payload):
    # check path
    for p in self.patterns:
      pattern: re.Pattern = p["pattern"]
      if pattern.findall(path):
        self.report(path, "query")
      if pattern.findall(payload):
        self.report(payload, "body")
