import angr
import networkx
import time
import csv

# angr.logging.basicConfig(level=angr.logging.DEBUG)

def check_file(path):
  p = angr.Project(path, load_options={"auto_load_libs": False})

  # 打印导入表，可以判断使用了哪些libc的函数
  obj = p.loader.main_object
  # help(obj)

  # .symtab 通过在不在判断
  section_names = list(map(lambda x: x.name, obj.sections.raw_list))
  # print('段的名称')
  # print(section_names)
  # print('是否是stripped的文件')
  # print(not '.symtab' in section_names)
  is_stripped = (not '.symtab' in section_names)

  # print('是否静态链接')
  # print(not '.dynsym' in section_names)
  is_statically_linked = (not '.dynsym' in section_names)

  imports = list(obj.imports.keys())
  # print('导入的函数')
  # print(imports)
  # print('是否有危险的导入函数')
  # print('system' in imports or 'execve' in imports)
  dangerous_import = ('system' in imports or 'execve' in imports)

  text_sec_names = []
  text_sec_size = 0
  for sec in obj.sections:
    if sec.is_executable and sec.occupies_memory:
      text_sec_size += (sec.max_addr - sec.min_addr)
      text_sec_names.append(sec.name)
  # text_sec = obj.sections
  # help(ent_sec)
  # print('代码段大小')
  # print(text_sec_size)
  # print('代码段数量')
  # print(len(text_sec_names))
  # print('是否有符号main')
  # print(obj.get_symbol("main") != 'None')
  text_sec_num = (len(text_sec_names))
  has_symbol_main = (obj.get_symbol("main") != 'None')

  # start = time.time()

  cfg = p.analyses.CFGFast()

  # print('分析消耗的时间')
  # print(time.time() - start)
  # # cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)

  # print('节点和边的数量')
  # print((len(cfg.graph.nodes()), len(cfg.graph.edges())))
  nodes_count = len(cfg.graph.nodes())
  edges_count = len(cfg.graph.edges())
  # print('环的数量')
  # 大一点的程序会炸。。。
  # print(len(list(networkx.simple_cycles(cfg.graph))))
  result = [is_stripped, is_statically_linked, dangerous_import, text_sec_size, text_sec_num, has_symbol_main,
            nodes_count, edges_count]
  result = [('1' if i else '0') if type(i) == bool else str(i) for i in result]
  return result


headers = ['is_stripped', 'is_static_link', 'has_malicious_import_function',
            'size_of_code_segment', 'num_of_code_segment', 'has_symbol_main', 'num_CFG_nodes', 'num_CFG_edges',"is_mal"]

if __name__ == '__main__':

  # print(check_file("./ok/hello"))
  # exit(0)
  result = []
  f = open('./model/features.csv', 'w', newline='',encoding="utf-8")
  csv_writer = csv.writer(f)
  csv_writer.writerow(headers)
  import os

  for root, dirs, files in os.walk('./malicious'):
    for file in files:
      if 'meterpreter' in file:
        continue
      path = os.path.join(root, file)
      print(path)

      t = check_file(path)
      t.append(1)
      result.append(t)
      t = [str(i) for i in t]
      csv_writer.writerow(t)

  for root, dirs, files in os.walk('./ok'):
    for file in files:
      path = os.path.join(root, file)
      print(path)

      t = check_file(path)
      t.append('0')
      result.append(t)
      t = [str(i) for i in t]
      csv_writer.writerow(t)
  # f.close()
