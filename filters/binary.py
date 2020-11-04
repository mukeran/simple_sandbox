import os
import json
import re

from filters.meta import BaseFilter
from engines.meta import Engine

class BinaryFilter(BaseFilter):
  def __init__(self):
    with open(os.path.join("./filters/datasets", "binary.json"), "r") as f:
      tmp = json.load(f)
      self.patterns = tmp["patterns"]
    for p in self.patterns:
      # print(p["pattern"])
      p["pattern"] = re.compile(p["pattern"].encode())

  def judge(self, type: Engine, data: dict):
    if type == Engine.HTTP:
      path = data['path']
      body = data['body']
      # check path
      for p in self.patterns:
        pattern: re.Pattern = p["pattern"]
        if pattern.findall(path):
          self.report(path, "query")
        if pattern.findall(body):
          self.report(body, "body")
    else:
      pass
