from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
import pandas as pd
from iec104Model import DATA_DIR
from joblib import dump
from sys import argv
from os.path import exists

file = "10122018-104Mega.pcapng.csv"
if len(argv) == 2:
    file = argv[1] if exists(argv[1]) else f"{DATA_DIR}/{argv[1]}"

iec104 = pd.read_csv(file, header=0, skipinitialspace=True)

x_train, x_test = train_test_split(iec104, train_size=2/3, test_size=1/3, shuffle=False, random_state=0)
nu = 0.03
one_class_svm = OneClassSVM(nu=nu, kernel = 'rbf', gamma = 0.1).fit(x_train)
dump(one_class_svm, f"{DATA_DIR}/one-class-svm.joblib")
prediction = one_class_svm.predict(x_test)

size = len(prediction)
t = [i for i in prediction if i == -1]
anomalies = len(t)
t = [i for i in prediction if i == 1]
ok = len(t)
perc_anom = anomalies/size

print(f"Nu is: {nu}")
print(f"Total number of samples: {size}")
print(f"Normal: {ok} ({100*(1-perc_anom):.2f}%)")
print(f"Anomalies: {anomalies} ({100*perc_anom:.2f}%)")