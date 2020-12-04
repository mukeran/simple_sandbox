import unittest
import predict
import tempfile
import time


class Tester(unittest.TestCase):
  def test_predict(self):
    tests = [
      ("<?php echo 1+1; ?>", 1),
      ('<?php system("ls"); ?>', 0)]
    p = predict.Predictor("./model/model.joblib")
    tmp_file = "/tmp/tmp.php"
    for t in tests:
      with open(tmp_file, "w")as f:
        f.write(t[0])
      result = p.predict(tmp_file)
      print(result)
      self.assertEqual(result, t[1])
