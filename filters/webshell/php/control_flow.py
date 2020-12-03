import subprocess
import os
import tempfile
import json

def merge_info(a: dict, b: dict):
  for k in a.keys():
    if k in b.keys():
      a[k] += b[k]
  return a

def parse_node(node):
  info = { 'loop': 0, 'command_execution': 0, 'eval': 0 }
  if type(node) == list:
    for elem in node:
      info = merge_info(info, parse_node(elem))
  elif type(node) == dict:
    for item in node.values():
      if type(item) == list:
        info = merge_info(info, parse_node(item))
        continue
      elif type(item) != dict:
        continue
      if 'nodeType' in item.keys():
        info = merge_info(info, parse_node(item))
    if node['nodeType'] == 'Expr_FuncCall':
      if node['name']['parts'][0] in ['system', 'shell_exec', 'exec', 'pcntl_exec', 'popen']:
        info['command_execution'] += 1
    if node['nodeType'] == 'Expr_Eval':
      info['eval'] += 1
    if node['nodeType'] == 'Stmt_For' or node['nodeType'] == 'Stmt_While' or node['nodeType'] == 'Stmt_Do':
      info['loop'] += 1
  return info
    

def extract_control_flow(code):
  tmp_file = tempfile.TemporaryFile()
  p = subprocess.Popen(['./php-parse', '-j', code], cwd=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor/nikic/php-parser/bin'), shell=False, stdout=tmp_file, stderr=subprocess.PIPE)
  p.wait()
  tmp_file.seek(0)
  content = tmp_file.read()
  tmp_file.close()
  ast = json.loads(content)
  return parse_node(ast)

# 机器学习，用 AST 提取特征并与样本比对
def check_php_by_control_flow(content):
  pass

def generate_control_flow_model():
  pass

if __name__ == '__main__':
  print(extract_control_flow('<?php eval("1+1"); ?>'))
