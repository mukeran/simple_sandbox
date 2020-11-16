from enum import Enum

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
