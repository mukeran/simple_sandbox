import joblib
import os
if __name__ == '__main__':
  import myfe
else:
  from . import myfe
from collections import OrderedDict
import pandas


class Predictor:
  def __init__(self, model_path):
    self.model = joblib.load(model_path)

  def is_malicious(self, file_path):
    if os.path.getsize(file_path) > 10 * 1024: # 过大文件获得 CFG 需要很长时间，直接跳过 CFG 分析，返回 True 表示需要使用沙箱检测
      return True
    if not os.path.exists(file_path):
      raise FileNotFoundError
    features = myfe.check_file(file_path)
    print(features)
    d = OrderedDict()
    for index in range(len(features)):
      d[myfe.headers[index]] = [features[index]]
    x = pandas.DataFrame.from_dict(d)
    y = self.model.predict(x)
    return y[0]


if __name__ == '__main__':
  p = Predictor("./model/model.joblib")
  print(bool(p.is_malicious("./ok/cat")))
