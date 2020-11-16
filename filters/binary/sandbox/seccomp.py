import sys

class SECCOMPSandbox:
  """
  Using simple SECCOMP based sandbox library locally
  """
  @staticmethod
  def check(binary_path: str):
    if not sys.platform.startswith('linux'):
      return False
