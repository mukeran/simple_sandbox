import joblib
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split, cross_val_predict
import os
import matplotlib.pyplot as plt


def train_and_dump(x_train, y_train, dump_path):
  model = RandomForestClassifier(
    criterion='gini', n_estimators=700,
    min_samples_split=10, min_samples_leaf=1,
    max_features='auto', oob_score=True,
    random_state=1, n_jobs=-1)
  model.fit(x_train, y_train)
  joblib.dump(model, os.path.join(dump_path, "model.joblib"))


def grade(model_path, x_test, y_test):
  model = joblib.load(os.path.join(model_path, "model.joblib"))
  print('准确率为：', round(accuracy_score(model.predict(x_test), y_test) * 100, 2))
  print('精确率为：', round(precision_score(model.predict(x_test), y_test) * 100, 2))
  print('召回率为：', round(recall_score(model.predict(x_test), y_test) * 100, 2))
  print('F1 score为：', round(f1_score(model.predict(x_test), y_test) * 100, 2))


# def show_matrix():
#     model=joblib.load("../model/forest-sql.joblib")
#     y_pred=cross_val_predict(model, all_features, target_features, cv=10)
#     sns.heatmap(confusion_matrix(target_features, y_pred),
#                 annot=True, fmt='3.0f', cmap="summer")
#     plt.title('Confusion_matrix', y=1.05, size=15)
#     plt.show()


def show_heatmap(traindf):
  co = traindf.corr()
  sns.heatmap(co, cmap='RdYlGn', linewidths=0.2)
  plt.show()


if __name__ == '__main__':
  work_path = r"./data"
  traindf = pd.read_csv(os.path.join(work_path, "features.csv"))
  # tt = traindf.isnull().sum().sort_values(ascending=False)
  target_features = traindf["is_benign"]
  all_features = traindf.drop(["is_benign"], axis=1)
  x_train, x_test, y_train, y_test = train_test_split(
    all_features, target_features, test_size=0.3, random_state=42
  )
  dump_path="./model"
  train_and_dump(x_train, y_train, "./model")
  grade(dump_path, x_test, y_test)
  # show_heatmap(traindf)
