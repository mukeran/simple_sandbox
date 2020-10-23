import abc
import logging
import re
from filters.meta import BaseFilter


class SqliFilter(BaseFilter):
  def __init__(self):
    BaseFilter.__init__(self, "sqli.json")
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

# alert tcp any any -> any $HTTP_PORTS (msg:"SQL Injection - Paranoid";flow:to_server,established;pcre:"/(\%27)|(\')|(\-\-)|(%23)|(#)/i"; classtype:Web-application-attack; sid:909900;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for typical SQL Injection attack";flow:to_server,established;pcre:"/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix"; classtype:Web-application-attack; sid:910001;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for detecting SQL Injection with the UNION keyword";flow:to_server,established;pcre:"/((\%27)|(\'))union/ix"; classtype:Web-application-attack; sid:910002;rev:5;)
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for detecting SQL Injection attacks on a MS SQL Server";flow:to_server,established;pcre:"/exec(\s|\+)+(s|x)p\w+/ix"; classtype:Web-application-attack; sid:910003;rev:5;)
