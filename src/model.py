from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
import pandas as pd
from joblib import dump
from iec104Model.src import CSV, DATA_DIR
import sys

def create_model(num=1):
    iec104 = pd.read_csv(CSV[str(num)], header=0, skipinitialspace=True)

    if "interval" in iec104.columns:
        iec104 = iec104.drop(columns=["relative_time_stamp"])

    print(iec104.head)

    x_train, x_test = train_test_split(iec104, train_size=2/3, test_size=1/3,
                                    shuffle=False, random_state=0)
    nu = 0.0188
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

if __name__ == "__main__":
    if len(sys.argv) > 1:
        create_model(sys.argv[1])
    else:
        create_model()

