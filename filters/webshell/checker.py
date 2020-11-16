from .meta import WebshellLang
from .php import check_php_by_control_flow

class Checker:
  @staticmethod
  def check(lang: WebshellLang, content: bytes):
    if lang == WebshellLang.PHP:
      result = check_php_by_control_flow(content)
      return result
    else:
      return None
