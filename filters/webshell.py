import logging
import os
import json
import re
from enum import Enum
from typing import Tuple

from filters.meta import BaseFilter
from engines.meta import Engine

class WebshellLang(Enum):
  PHP = 0
  ASP = 1
  JSP = 2

  @staticmethod
  def from_string(s: str):
    if s.lower() == 'php':
      return WebshellLang.PHP
    elif s.lower() == 'asp':
      return WebshellLang.ASP
    elif s.lower() == 'jsp':
      return WebshellLang.JSP
    return None

class WebshellFilter(BaseFilter):
  def __init__(self):
    with open(os.path.join('./filters/datasets', 'webshell.json'), 'r') as f:
      data = json.load(f)
      self.patterns = data['patterns']
      self.languages = data['languages']
    for p in self.patterns:
      p['pattern'] = re.compile(p['pattern'].encode(), re.IGNORECASE | re.DOTALL | re.MULTILINE)
    for lang in self.languages:
      lang['pattern'] = re.compile(lang['pattern'].encode(), re.IGNORECASE | re.DOTALL | re.MULTILINE)

  def judge_by_pattern(self, content):
    for p in self.patterns:
        pattern: re.Pattern = p['pattern']
        match = pattern.findall(content)
        if match:
          return match
    return False

  def preprocess(self, content):
    parts = []
    for lang in self.languages:
      pattern: re.Pattern = lang['pattern']
      result = pattern.finditer(content)
      if result:
        for match in result:
          match: re.Match
          parts.append((WebshellLang.from_string(lang['lang']), match.groupdict()['code']))
    return parts

  @staticmethod
  def judge_by_ast(lang: WebshellLang, content: bytes):
    pass

  def judge(self, type: Engine, data: dict):
    if type == Engine.HTTP:
      path = data['path']
      body = data['body']
      if self.judge_by_pattern(path):
        self.report(path, 'query')
      if self.judge_by_pattern(body):
        self.report(body, 'body')
    elif type == Engine.FILE:
      content: bytes
      path: str = data['path']
      with open(path, 'rb') as f:
        content = f.read()
      result = self.judge_by_pattern(content)
      if result:
        self.report(result, path)
      parts = self.preprocess(content)
      if not parts:
        return
      for part in parts:
        part: Tuple[WebshellLang, bytes]
        result = self.judge_by_ast(part[0], part[1])
        if result:
          self.report(result, path)
