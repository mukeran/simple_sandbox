import os
from . import control_flow
import joblib
from collections import OrderedDict
import pandas


class Predictor:
  def __init__(self, model_path):
    self.model = joblib.load(model_path)

  def predict(self, file_path):
    if not os.path.exists(file_path):
      raise FileNotFoundError
    features = control_flow.extract_control_flow(file_path)
    # print(features)
    d = OrderedDict()
    for k, v in features.items():
      d[k] = [v]
    x = pandas.DataFrame.from_dict(d)
    y = self.model.predict(x)
    return y[0]


if __name__ == '__main__':
  p = Predictor("./model/model.joblib")
  print(bool(p.predict("./tests/sys_ls.php")))
