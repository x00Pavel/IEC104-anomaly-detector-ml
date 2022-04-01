from os.path import join, dirname, realpath
from os import getcwd

DATA_DIR = join(dirname(realpath(__file__)), "data")

PCAP = {"1": join(DATA_DIR, "mega104-17-12-18.pcapng"),
        "2": join(DATA_DIR, "10122018-104Mega.pcapng"),
        "3": join(DATA_DIR, "10122018-104Mega-anomaly.pcapng")}

CSV = {"1": join(DATA_DIR, "mega104-17-12-18.pcapng.csv"),
       "2": join(DATA_DIR, "10122018-104Mega.pcapng.csv"),
       "3": join(DATA_DIR, "10122018-104Mega-anomaly.pcapng.scv")}
