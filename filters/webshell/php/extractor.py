import os
import csv

from control_flow import extract_control_flow


class Extractor:
  HEADER = ['loop', 'command_execution', 'eval', 'get_post_request', 'encryption', 'hash',
            'long_length_variable_name', 'condition', 'long_length_string', 'dynamic_function_call',
            'binary_op_between_string', 'dynamic_variable_name', 'is_benign']

  def __init__(self):
    self.csv_file = open("./data/features.csv", "w", encoding="utf-8", newline='')
    self.csv_writer = csv.writer(self.csv_file)
    self.csv_writer.writerow(self.HEADER)

  def extract(self, dataset_path, typ):
    files = os.listdir(dataset_path)
    for file in files:
      if ".php" not in file:
        continue
      filename = os.path.join(dataset_path, file)
      features = extract_control_flow(filename)
      if not features:
        continue
      v = []
      count_0 = 0
      for h in self.HEADER:
        if h == 'is_benign':
          continue
        try:
          value = features[h]
        except:
          value = 0
        if value == 0:
          count_0 += 1
        v.append(value)
      if count_0 == len(self.HEADER):
        continue
      v.append(typ)
      self.csv_writer.writerow(v)
      # print()


if __name__ == '__main__':
  e = Extractor()
  # e.extract(r"./data/test", 0)
  e.extract(r"/mnt/f/NutStore/Courses/cbj实验/simple_sandbox/filters/webshell/php/data/webshells", 0)
  e.extract(r"/mnt/f/NutStore/Courses/cbj实验/simple_sandbox/filters/webshell/php/data/normal", 1)
