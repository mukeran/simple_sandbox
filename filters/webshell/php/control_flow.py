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
  info = { 'loop': 0, 'command_execution': 0, 'eval': 0, 'get_post_request': 0, 'encryption': 0, 'hash': 0, 'long_length_variable_name': 0, 'condition': 0, 'long_length_string': 0, 'dynamic_function_call': 0, 'binary_op_between_string': 0, 'dynamic_variable_name': 0 }
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
      if 'parts' in node['name'] and node['name']['parts'][0].lower() in ['system', 'shell_exec', 'exec', 'pcntl_exec', 'popen', 'passthru']:
        info['command_execution'] += 1
      elif 'parts' in node['name'] and node['name']['parts'][0].lower() in ['base64_decode', 'openssl_decrypt', 'openssl_encrypt']:
        info['encryption'] += 1
      elif 'parts' in node['name'] and node['name']['parts'][0].lower() in ['md5', 'sha1', 'hash']:
        info['hash'] += 1
      if 'nodeType' in node['name']:
        info['dynamic_function_call'] += 1
    elif node['nodeType'] == 'Expr_Eval':
      info['eval'] += 1
    elif node['nodeType'] == 'Stmt_For' or node['nodeType'] == 'Stmt_While' or node['nodeType'] == 'Stmt_Do':
      info['loop'] += 1
    elif node['nodeType'] == 'Expr_Variable':
      if type(node['name']) != str:
        info['dynamic_variable_name'] += 1
      elif node['name'].lower() in ['_get', '_post', '_request']:
        info['get_post_request'] += 1
      if len(node['name']) >= 10:
        info['long_length_variable_name'] += 1
    elif node['nodeType'] == 'Stmt_If' or node['nodeType'] == 'Stmt_Else':
      info['condition'] += 1
    elif node['nodeType'] == 'Scalar_String':
      if len(node['value']) >= 16:
        info['long_length_string'] += 1
    elif node['nodeType'] == 'Expr_ShellExec':
      info['command_execution'] += 1
    elif node['nodeType'].startswith('Expr_BinaryOp'):
      if ('left' in node and node['left']['nodeType'] == 'Scalar_String') or ('right' in node and node['right']['nodeType'] == 'Scalar_String'):
        info['binary_op_between_string'] += 1
  return info
    

def extract_control_flow(code):
  tmp_file = tempfile.TemporaryFile()
  cwd = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor/nikic/php-parser/bin')
  print(code)
  p = subprocess.Popen(['./php-parse', '-j', code], cwd=cwd, shell=False, stdout=tmp_file, stderr=subprocess.PIPE)
  p.wait()
  tmp_file.seek(0)
  content = tmp_file.read()
  tmp_file.close()
  try:
    ast = json.loads(content)
  except Exception as e:
    # print(e)
    # return
    return { 'loop': 0, 'command_execution': 0, 'eval': 0, 'get_post_request': 0, 'encryption': 0, 'hash': 0, 'long_length_variable_name': 0, 'condition': 0, 'long_length_string': 0, 'dynamic_function_call': 0, 'binary_op_between_string': 0, 'dynamic_variable_name': 0 }
  return parse_node(ast)

if __name__ == '__main__':
  print(extract_control_flow('''<?php 
    $a = ('!'^'@').'s'.'s'.'e'.'r'.'t';
    $b='_'.'P'.'O'.'S'.'T';
    $c=$$b;
    $a($c['x']);
?>'''))
