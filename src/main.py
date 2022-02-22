from iec104Model import DATA_DIR
import pyshark
from os.path import join

pcap_file = join(DATA_DIR, "10122018-104Mega.pcapng")
packets = pyshark.FileCapture(pcap_file)


p = packets[1]
print(p.layers)
