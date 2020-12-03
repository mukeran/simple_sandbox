import logging
import subprocess
import json
import os
import tempfile
import shutil

class ContainerSandbox:
  """
  Using Linux namespace
  """
  @staticmethod
  def init():
    if not os.path.exists('./external/binary_sandbox/sandbox'):
      logging.fatal('Please make binary sandbox in external/binary_sandbox before using')

  @staticmethod
  def check(binary_path: str):
    tmpdir = tempfile.TemporaryDirectory(prefix='sandbox_')
    temp_stdout = tempfile.TemporaryFile()
    temp_stderr = tempfile.TemporaryFile()
    logging.debug('Sandbox temp dir: {}'.format(tmpdir.name))
    p = subprocess.Popen([os.path.join(os.getcwd(), 'external/binary_sandbox/sandbox'), binary_path], stdout=temp_stdout, stderr=temp_stderr, cwd=tmpdir.name)
    p.wait()
    tmpdir.cleanup()
    temp_stderr.seek(0)
    err = temp_stderr.readlines()
    temp_stderr.close()
    if len(err) != 0:
      logging.error('Sandbox error, msg: {}'.format(err))
      return False
    temp_stdout.seek(0)
    out = temp_stdout.readlines()
    temp_stdout.close()
    logging.debug('Sandbox stdout: {}'.format(out))
    try:
      result = json.loads(out[-1])
    except Exception as e:
      return False
    return 'Type: {}; Extra: {}'.format(result['type'], result['extra'])
