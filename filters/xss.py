import abc
import logging
import re
from filters.meta import BaseFilter


class XSSFilter(BaseFilter):
    def __init__(self):
        BaseFilter.__init__(self, "xss.json")
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

# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for simple CSS attack";flow:to_server,established;pcre:"/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix"; classtype:Web-application-attack; sid:910004;rev:5;)
#
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Regex for img src CSS attack";flow:to_server,established;pcre:"/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I"; classtype:Web-application-attack; sid:910005;rev:5;)
#
#
# alert tcp any any -> any $HTTP_PORTS (msg:"Paranoid regex for CSS attacks";flow:to_server,established;pcre:"/((\%3C)|<)[^\n]+((\%3E)|>)/I"; classtype:Web-application-attack; sid:910006;rev:5;)