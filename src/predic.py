from joblib import load
from os.path import exists
from iec104Model import DATA_DIR
from sys import argv
import pandas as pd

model = f"{DATA_DIR}/one-class-svm.joblib"
assert exists(model), "No SVM model exists"
assert len(argv) == 2, "No file specified"

svm = load(model)
data = pd.read_csv(argv[1])

prediction = svm.predict(data)
size = len(prediction)
t = [i for i in prediction if i == -1]
anomalies = len(t)
t = [i for i in prediction if i == 1]
ok = len(t)
perc_anom = anomalies/size

print(f"Total number of samples: {size}")
print(f"Normal: {ok} ({100*(1-perc_anom):.2f}%)")
print(f"Anomalies: {anomalies} ({100*perc_anom:.2f}%)")