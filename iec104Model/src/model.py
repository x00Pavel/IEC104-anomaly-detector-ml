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


def evaluate_numbers():
    # print(iec104.head)
    iec_1 = pd.read_csv(CSV["1"], header=0, skipinitialspace=True).drop(columns=["relative_time_stamp"])
    iec_2 =  pd.read_csv(CSV["2"], header=0, skipinitialspace=True).drop(columns=["relative_time_stamp"])
    # iec104 = pd.read_csv(CSV[str(num)], header=0, skipinitialspace=True).drop(columns=["relative_time_stamp"])

    x_train_1, x_test_1 = train_test_split(iec_1, train_size=2/3, test_size=1/3,
                                    shuffle=False, random_state=0)
    x_train_2, x_test_2 = train_test_split(iec_2, train_size=2/3, test_size=1/3,
                                    shuffle=False, random_state=0)
    
    result_pd = []
    i = 0.01

    while i < 0.031:
        nu = i
        ent = [i]
        for train, test in [(x_train_1, x_test_1), (x_train_2, x_test_2)]:
            one_class_svm = OneClassSVM(nu=nu, kernel = 'rbf', gamma = 0.1).fit(train)
            prediction = one_class_svm.predict(test)
            # dump(one_class_svm, f"{DATA_DIR}/one-class-svm.joblib")
            
            t = [i for i in prediction if i == -1]
            anomalies = len(t)
            size = len(test)
            perc_anom = anomalies/size
            ent.append([perc_anom*100, (1 - perc_anom) * 100])

        result_pd.append(ent)
        i += 0.002

    df = pd.DataFrame(result_pd, columns=["nu", "anomalies_1", "ok_2", "anomalies_2", "ok_2"])
    df.to_csv("./data/pandas-df.csv")
    print(df.head)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        create_model(sys.argv[1])
    else:
        create_model()

