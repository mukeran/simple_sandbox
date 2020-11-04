import os
import json
import re

from filters.meta import BaseFilter
from engines.meta import Engine

class SqliFilter(BaseFilter):
  def __init__(self):
    with open(os.path.join("./filters/datasets", "sqli.json"), "r") as f:
      tmp = json.load(f)
      self.patterns = tmp["patterns"]
    for p in self.patterns:
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

# alert tcp any any -> any $HTTP_PORTS (msg:"SQL Injection - Paranoid";flow:to_server,established;pcre:"/(\%27)|(\')|(\-\-)|(%23)|(#)/i"; classtype:Web-application-attack; sid:909900;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for typical SQL Injection attack";flow:to_server,established;pcre:"/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix"; classtype:Web-application-attack; sid:910001;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for detecting SQL Injection with the UNION keyword";flow:to_server,established;pcre:"/((\%27)|(\'))union/ix"; classtype:Web-application-attack; sid:910002;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for detecting SQL Injection attacks on a MS SQL Server";flow:to_server,established;pcre:"/exec(\s|\+)+(s|x)p\w+/ix"; classtype:Web-application-attack; sid:910003;rev:5;)
