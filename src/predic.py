from joblib import load
from iec104Model.src import DATA_DIR, CSV
from sys import argv
import pandas as pd

def predict(num=1):
    model = f"{DATA_DIR}/one-class-svm.joblib"


    svm = load(model)
    data = pd.read_csv(CSV[str(num)]).drop(columns=["relative_time_stamp"])

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

if __name__ == "__main__":
    if len(argv) > 1:
        predict(argv[1])
    else:
        predict()
