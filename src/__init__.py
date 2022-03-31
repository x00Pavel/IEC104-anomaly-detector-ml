from os.path import join

DATA_DIR = "/home/xyadlo00/studies/FIT/MITAI/1-rocnik/letni/PDS/proj/iec104Model/src/data"

PCAP = {"1": join(DATA_DIR, "mega104-17-12-18.pcapng"),
        "2": join(DATA_DIR, "10122018-104Mega.pcapng"),
        "3": join(DATA_DIR, "10122018-104Mega-anomaly.pcapng")}

CSV = {"1": join(DATA_DIR, "mega104-17-12-18.pcapng.csv"),
       "2": join(DATA_DIR, "10122018-104Mega.pcapng.csv"),
       "3": join(DATA_DIR, "10122018-104Mega-anomaly.pcapng.scv")}
